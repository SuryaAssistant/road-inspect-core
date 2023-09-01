#=======================================================================
# road-inspect-core
#
# This program is used to connect client and IOTA tangle 
# for road-inspect.
#
# This program can be used to give signature to the data by using ECDSA.
#
# More information : 
# https://github.com/SuryaAssistant/road-inspect-core
#
# Apache-2.0 License
#=======================================================================

# Gateway Properties
from config.config import *
import iota_client

# Websocket
import eventlet
import socketio

# ECC Digital Signature Properties
from ellipticcurve import Ecdsa, PrivateKey, PublicKey, Signature
from ellipticcurve.utils.file import File

# Other Properties
import subprocess
import json
import time
import os


client_data = ""
send_addr = ""
tangle_msg_id = ""

home_directory = os.path.expanduser("~")
private_key_folder = home_directory + '/.road-inspect-core'
private_key_path = home_directory + '/.road-inspect-core/privateKey.pem'

#=======================================================================
# Function to Upload Data to IOTA Tangle
# Parameter:
# - input_data : Series of data to be uploaded
# - index_msg  : tag index in IOTA Tangle. For easy search by tag index
#=======================================================================
def upload(data, index_msg):
    timestamp = str(int(time.time()))
    encoded_data = data.encode()
    message = ('"message":' + '{"timestamp":' + timestamp + 
        ',"data":' + data + '}')
        
    # Read private key for signature
    privateKey =  PrivateKey.fromPem(File.read(private_key_path))
    # Create public key 
    publicKey = privateKey.publicKey()
    # Create Signature
    signature = Ecdsa.sign(message, privateKey).toBase64()
    # Create JSON like format
    payload = ('{' + message + 
        ',"publicKey":"' + publicKey.toCompressed() + 
        '","signature":"' + signature + '"}')
    payload_int = payload.encode("utf8")

    # upload to tangle
    tangle_return = client.message(index=index_msg, data=payload_int)
    global tangle_msg_id
    tangle_msg_id = tangle_return['message_id']
    
#=======================================================================
# Function to create and save ECDSA private key
# Parameter: None
#=======================================================================
def ECDSA_begin():
    # ECDSA CONFIG
    #if folder is not exist, create folder
    if os.path.exists(private_key_folder) == False:
        os.mkdir(private_key_folder)

    #if privateKey is not exist, create pem file
    if os.path.exists(private_key_path) == False:
        # Create new privateKey
        privateKey = PrivateKey()
        privateKeyPem = privateKey.toPem()
        
        f = open(private_key_path, "w")
        f.write(privateKeyPem)
        f.close()




#=======================================================================
# Function to get all verified message in index
#
# Give return a JSON compatible and verified by ECDSA
#=======================================================================
def get_valid_msg():
	try:
		#===============================================================
		# Signature verification
		#
		# This process will result message with JSON compatible 
		# format only and valid that verified by ECDSA.
		#===============================================================
		
		# Read all message in road-inspect-index
		msg_id_list= client.get_message_index(road_inspect_index)
		complete_data = "["
		
		# get payload for every message ID
		for i in range(len(msg_id_list)):
			full_data = client.get_message_data(msg_id_list[i]) 
			
			# do ECDSA verification
			payload_byte = full_data["payload"]["indexation"][0]["data"]
			full_message=''
			for x in range(len(payload_byte)):
				full_message += chr(payload_byte[x]) 
			
			# extract message
			msg_start_index = full_message.find("message") - 1
			msg_end_index = full_message.find("publicKey") - 2
			message = full_message[msg_start_index:msg_end_index]
						
			# get signature
			try:
				data_json = json.loads(full_message)
				signature = data_json["signature"]
			except ValueError:
				print("Data Error: Received data is not in JSON compatible")
				continue
				
			# get this gateway publicKey
			home_directory = os.path.expanduser("~")
			key_path = home_directory + '/.road-inspect-core/privateKey.pem'
			
			privateKey =  PrivateKey.fromPem(File.read(key_path))
			publicKey = privateKey.publicKey()
			#publicKey_pem = publicKey.toPem()
			
			# ECDSA verification
			signatureToVerify = Signature.fromBase64(signature)
			if Ecdsa.verify(message, signatureToVerify, publicKey):
				complete_data += '[{"msgID":"' + msg_id_list[i] + '"},' + full_message + ']'
				if i < len(msg_id_list)-1:
					complete_data += ","
			#else:
				#print("Not a Payload from This Gateway")
				
		# delete latest ',' if found
		if complete_data[len(complete_data)-1] == ',':
			complete_data = complete_data[:-1]
		complete_data += "]"
		
		valid_json = json.loads(complete_data)
		
		#===============================================================
		# Sort by timestamp
		#
		# This process will sort JSON by it timestamp
		#===============================================================
		# Remove dictionaries without 'timestamp' key
		data_with_timestamp = [entry for entry in valid_json if 'timestamp' in entry[1]['message']]

		# Sort the data by 'timestamp'
		sorted_json = sorted(data_with_timestamp, key=lambda x: x[1]['message']['timestamp'])
		
		return sorted_json
		
	except Exception as e:
		print("An exception occurred:", type(e).__name__)
		print("Exception details:", str(e))
		
		
		
#=======================================================================
# Function to filter unfinished road report
#
# Used for main homepage
#=======================================================================
def get_resume(emit_address):
	try :
		sorted_valid_json = get_valid_msg()
		
		#===============================================================
		# UTXO for 'type' model
		#
		# This process will update 'type' value 
		# from 'report' to 'fixing' or 'finish'
		#
		# If there is 'fixing' or 'finish' type, check it ticket
		# If match, set report_json type to 'fixing' or 'finish'
		#===============================================================
		report_json = [entry for entry in sorted_valid_json if entry[1]['message']['data']['type'] == 'report']
		
	
		for i in range(len(sorted_valid_json)):
			sorted_json_type = sorted_valid_json[i][1]['message']['data']['type']
			
			#================= Fixing ========================================
			if sorted_json_type == 'fixing':
				target_ticket = sorted_valid_json[i][1]['message']['data']['ticket']
				for j in range(len(report_json)):
					if report_json[j][0]['msgID'] == target_ticket:
						report_json[j][1]['message']['data']['type'] = 'fixing'
						
			#================= Finish ========================================
			elif sorted_json_type == 'finish':
				target_ticket = sorted_valid_json[i][1]['message']['data']['ticket']
				for j in range(len(report_json)):
					if report_json[j][0]['msgID'] == target_ticket:
						report_json[j][1]['message']['data']['type'] = 'finish'


		#===============================================================
		# Non-finish report
		#
		# This process will only give report that not finished yet
		#===============================================================
		resume_json = [entry for entry in report_json if entry[1]['message']['data']['type'] != 'finish']
		
		sio.emit(emit_address, resume_json)

	except Exception as e:
		print("An exception occurred:", type(e).__name__)
		print("Exception details:", str(e))



#=======================================================================
# Function to get information of a ticket ID
#
# return JSON data that contain ticket ID and other linked message
#=======================================================================
def ticket_info(ticketID, emit_address):
	try:
		ticket_output = []
		ticket_reference = ""
		has_ticket = False
		sorted_valid_json = get_valid_msg()
		
		# get main message data
		for i in range(len(sorted_valid_json)):
			if sorted_valid_json[i][0]['msgID'] == ticketID:
				ticket_output.append(sorted_valid_json[i])
				if 'ticket' in sorted_valid_json[i][1]['message']['data']:
					has_ticket = True
					ticket_reference = sorted_valid_json[i][1]['message']['data']['ticket']
					
				# remove from list
				sorted_valid_json.pop(i)
				break
		
		if has_ticket == True:
			# search main id
			for i in range(len(sorted_valid_json)):
				if sorted_valid_json[i][0]['msgID'] == ticketID:
					ticket_output.append(sorted_valid_json[i])
					
					# remove from list
					sorted_valid_json.pop(i)
					break
		
		# search other referenced data until end of line
		for i in range(len(sorted_valid_json)):
			if 'ticket' in sorted_valid_json[i][1]['message']['data']:
				if sorted_valid_json[i][1]['message']['data']['ticket'] == ticketID:
					ticket_output.append(sorted_valid_json[i])
				
		sio.emit(emit_address, ticket_output)

	except Exception as e:
		print("An exception occurred:", type(e).__name__)
		print("Exception details:", str(e))

#=======================================================================
# Function to act based on input command in API
# Parameter:
# - command : command to do
# - parameter_value : value to input in command
# - return_topic : topic used to send MQTT
#=======================================================================
def do_command(full_input_command):
	parsing_data = full_input_command.split('/')
	command = parsing_data[0]
	parameter_value = parsing_data[1]
	clientSID = str(parsing_data[2].replace("'", ""))

    # Convert compressed public key to PEM format
	# Format: convert_to_pem/<compressedPublicKey>/<return_topic>
	if command == 'convert_to_pem':
		try :
			compressedPublicKey = parameter_value
			convert_publicKey = PublicKey.fromCompressed(compressedPublicKey)
			publicKey_pem = convert_publicKey.toPem()
			sio.emit(clientSID, publicKey_pem)
		except ValueError :
			sio.emit(clientSID, "Error to convert compressed public key to PEM format")
		except :
			sio.emit(clientSID, "Unknown error")

    # Upload data to tangle
    # Format: data/<parameter_value>/<return_topic>/<specified_tag_index>
	elif command == 'data':
		try :
			parameter_value = parameter_value.replace("'", '"')
			tag_index = parsing_data[3]
			upload(parameter_value, tag_index)
			sio.emit(clientSID, tangle_msg_id)

		except ValueError :
			sio.emit(clientSID, "Error to upload to Tangle")
		except IndexError :
			sio.emit(clientSID, "Format command not found")
		except :
			sio.emit(clientSID, "Unknown error")
			
	elif command == 'resume':
		try :
			get_resume(clientSID)
		except : 
			sio.emit(clientSID, "Error")

	elif command == 'ticket':
		try :
			ticket_info(parameter_value, clientSID)
		except : 
			sio.emit(clientSID, "Error")

# Start websocket
sio = socketio.Server(cors_allowed_origins="*")
app = socketio.WSGIApp(sio)

@sio.on('connect')
def connect(sid, environ):
    print(f'Client {sid} connected')

@sio.on('disconnect')
def disconnect(sid):
    print(f'Client {sid} disconnected')

@sio.on('submit')
def message(sid, inputMessage):
    print("INPUT ===> " + inputMessage)
    # check inputMessage structure
    # if the message command format is not fulfilled, skip
    # minimum format command ==> input_command/input_value/return_topic
    if '/' in inputMessage:
        if len(inputMessage.split('/')) >= 3:
            # Do message based on it command function
            do_command(inputMessage)

#=======================================================================
# Main program
# In first run, it will:
# - Create Random Private and Public Key
# 
# Next, it will act based on input command from MQTT input.
#=======================================================================
if __name__ == "__main__":
    # Configure ECDSA
    ECDSA_begin()
    
    # Test connection with permanode
    client = iota_client.Client(nodes_name_password=[[chrysalis_url]])
    print(client.get_info())

    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', 8765)), app)