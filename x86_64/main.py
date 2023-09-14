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
import sha3
import json
import time
import os

client_data = ""
send_addr = ""
tangle_msg_id = ""

# path
home_directory = os.path.expanduser("~")
private_key_folder = home_directory + '/.road-inspect-core'
private_key_path = home_directory + '/.road-inspect-core/privateKey.pem'

blockchain_index_json_path = home_directory + '/.road-inspect-core/data.json'

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
    
    # If there is new submitted message, read data.json and append new data
    new_data_str = '[{"msgID":"' + tangle_msg_id + '"},' + payload + ']'
    # load as JSON
    recent_data = json.loads(new_data_str)
    # update data.json
    with open(blockchain_index_json_path, 'r') as json_file:
        existing_data = json.load(json_file)
    existing_data.append(recent_data)
    # Save the updated JSON data back to the file
    with open(blockchain_index_json_path, 'w') as json_file:
        json.dump(existing_data, json_file, indent=4)

    print("New data added to record")


    return tangle_msg_id

    
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
# Function to create a new road report
# parameter:
#    - msg_data : all data to upload (in JSON compatible format)
#    - emit_address : address to return the status to client
#
# return IOTA Tangle msg_id if success
#=======================================================================
def create_report(msg_data, emit_address):
    try:
        # must support JSON compatible format
        inputJSON = json.loads(msg_data)
        
        # make sure type is correct
        if inputJSON['type'] == 'report':
            # bypass process
            upload_status = upload(msg_data, road_inspect_index)
            print('Create report status : ' + upload_status)
            sio.emit(emit_address, upload_status)
            return

    except Exception as e:
        print("An exception occurred:", type(e).__name__)
        print("Exception details:", str(e))
        error_msg = "Error to upload: " + str(e)
        sio.emit(emit_address, error_msg)

#=======================================================================
# Function to update road report
# parameter:
#    - reference_ticket : latest ticket from main branch report
#    - user_key : key to unlock the report
#    - emit_address : address to return the status to client
#
# return IOTA Tangle msg_id if success
#=======================================================================
def update_report(last_ticket, user_key, emit_address):
    try:
        # calculate user key hash for verification
        keccak256 = sha3.keccak_256()
        keccak256.update(user_key)
        user_keyword_hash = str(keccak256.hexdigest())
        
        # search reference in copied blockchain data
        saved_json = []
        
        with open(blockchain_index_json_path, 'r') as json_file:
            saved_json = json.load(json_file)
            
        for i in range(len(saved_json)):
            if saved_json[i][0]['msgID'] == last_ticket:
                # create new report structure
                update_report = ''
                update_ticket = ''
                prev_type = saved_json[i][1]['message']['data']['type']
                
                # if prev report is report
                if prev_type == 'report':
                    update_type = '{"type":"fixing",'
               
               # if prev report is fixing
                elif prev_type == 'fixing':
                    update_type = '{"type":"finish",'
                    
                else:
                    return
                
                # else, return error
                update_issuer = '"issuer":"' + saved_json[i][1]['message']['data']['issuer'] + '",'
                update_ticket = '"ticket":"' + saved_json[i][0]['msgID'] + '",'
                update_roadName = '"roadName":"' + saved_json[i][1]['message']['data']['roadName'] + '",'
                update_lat = '"lat":"' + saved_json[i][1]['message']['data']['lat'] + '",'
                update_long = '"long":"' + saved_json[i][1]['message']['data']['long'] + '",'
                update_desc = '"desc":"' + saved_json[i][1]['message']['data']['desc'] + '",'
                update_hashKey = '"hashKey":"' + saved_json[i][1]['message']['data']['hashKey'] + '"}'
                
                update_message = update_type + update_issuer + update_ticket + update_roadName + update_lat + update_long + update_desc + update_hashKey
                
                # check is target has key is same or not
                if user_keyword_hash == saved_json[i][1]['message']['data']['hashKey']:
                    print('Uploading update')
                    upload_status = upload(update_message, road_inspect_index)
                    print('Update report status from ' + prev_type + ' to ' + update_type)
                    print('Update status : ' + upload_status)
                    sio.emit(emit_address, upload_status)
                    return
                
                else :
                    # tell client that the key is wrong
                    sio.emit(emit_address, 'Error: Key is not match')
                    return
          
    except KeyError:
        sio.emit(emit_address, "Error: key is not match")
        
    except Exception as e:
        print("An exception occurred:", type(e).__name__)
        print("Exception details:", str(e))
        error_msg = "Error to upload: " + str(e)
        sio.emit(emit_address, error_msg)


#=======================================================================
# Function to get all verified message in index
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

        # prepare ecdsa key
        privateKey =  PrivateKey.fromPem(File.read(private_key_path))
        publicKey = privateKey.publicKey()
        #publicKey_pem = publicKey.toPem()
                
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
            
            # ECDSA verification
            signatureToVerify = Signature.fromBase64(signature)
            if Ecdsa.verify(message, signatureToVerify, publicKey):
                complete_data += '[{"msgID":"' + msg_id_list[i] + '"},' + full_message + ']'
                if i < len(msg_id_list)-1:
                    complete_data += ","
                
        # delete latest ',' if found
        if complete_data[len(complete_data)-1] == ',':
            complete_data = complete_data[:-1]
        complete_data += "]"

        valid_json = json.loads(complete_data)

        #===============================================================
        # Sort by timestamp
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
# Used for main homepage
#=======================================================================
def get_resume(emit_address):
    try :
        sorted_valid_json = []
        
        # Read the JSON data from the file
        with open(blockchain_index_json_path, 'r') as json_file:
            sorted_valid_json = json.load(json_file)

        #===============================================================
        # UTXO for 'type' model
        #
        # This process will update 'type' value 
        # from 'report' to 'fixing' or 'finish'
        #
        # If there is 'fixing' or 'finish' type, check it ticket
        # If match, replace with new 'fixing' or 'finish'
        #===============================================================
        report_json = [entry for entry in sorted_valid_json if entry[1]['message']['data']['type'] == 'report']
        

        for i in range(len(sorted_valid_json)):
            sorted_json_type = sorted_valid_json[i][1]['message']['data']['type']
            
            #================= Fixing ========================================
            if sorted_json_type == 'fixing':
                target_ticket = sorted_valid_json[i][1]['message']['data']['ticket']
                for j in range(len(report_json)):
                    if report_json[j][0]['msgID'] == target_ticket:
                        report_json[j] = sorted_valid_json[i]
                        
            #================= Finish ========================================
            elif sorted_json_type == 'finish':
                target_ticket = sorted_valid_json[i][1]['message']['data']['ticket']
                for j in range(len(report_json)):
                    if report_json[j][0]['msgID'] == target_ticket:
                        report_json[j] = sorted_valid_json[i]

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
# return JSON data that contain ticket ID and other linked message
#=======================================================================
def search_backward(backward_ticket):
    backward_result = []
    id_to_search = backward_ticket
    is_search = True

    json_db = []
    # Read the JSON data from the file
    with open(blockchain_index_json_path, 'r') as json_file:
        json_db = json.load(json_file)
    
    while(is_search == True):
        for i in range(len(json_db)):
            if json_db[i][0]['msgID'] == id_to_search:
                backward_result.append(json_db[i])
                
                # check if this data has 'ticket' for reference
                if 'ticket' in json_db[i][1]['message']['data']:
                    # search again
                    id_to_search = json_db[i][1]['message']['data']['ticket']
                    # reset while loop
                    i = len(json_db)-1
                
                # if no ticket, end while loop
                else:
                    is_search = False
    
    return backward_result



def search_forward(forward_ticket):
    forward_result = []
    id_to_search = forward_ticket

    json_db = []
    # Read the JSON data from the file
    with open(blockchain_index_json_path, 'r') as json_file:
        json_db = json.load(json_file)

    for i in range(len(json_db)):
        if 'ticket' in json_db[i][1]['message']['data']:
            if json_db[i][1]['message']['data']['ticket'] == id_to_search:
                forward_result.append(json_db[i])
                
                # search once again
                id_to_search = json_db[i][0]['msgID']
                for j in range(len(json_db)):
                    if 'ticket' in json_db[j][1]['message']['data']:
                        if json_db[j][1]['message']['data']['ticket'] == id_to_search:
                            forward_result.append(json_db[j])
                            
                            # immidiately return
                            return forward_result
                
                # if second search didnt give result
                # immidiately return
                return forward_result
            
    return forward_result


def ticket_info(ticketID, emit_address):
    try:
        ticket_output = []
        
        sorted_valid_json = []        
        # Read the JSON data from the file
        with open(blockchain_index_json_path, 'r') as json_file:
            sorted_valid_json = json.load(json_file)
        
        # get main message data
        for i in range(len(sorted_valid_json)):
            if sorted_valid_json[i][0]['msgID'] == ticketID:
                ticket_output.append(sorted_valid_json[i])
                
                # if has reference ticket, do search backward
                if 'ticket' in sorted_valid_json[i][1]['message']['data']:
                    # search backward
                    ticket_output += search_backward(sorted_valid_json[i][1]['message']['data']['ticket'])
        
                # search forward
                ticket_output += search_forward(ticketID)

        # send result to client
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
            sio.emit(clientSID, "Error to process public key")

    # Create a road report
    # Format: create/<parameter_value>/<return_topic>
    elif command == "create":
        try:
            parameter_value = parameter_value.replace("'", '"')
            create_report(parameter_value, clientSID)
        except : 
            sio.emit(clientSID, "Error")
            
    # Update status of road report
    # Format: update/<parameter_value>/<return_topic>/<user_key>
    elif command == "update":
        try:
            # Calculate user keyword hash
            parameter_value = parameter_value.replace("'", '"')
            user_keyword = parsing_data[3].encode('utf-8')
            update_report(parameter_value, user_keyword, clientSID)
        except Exception as e:
            print("An exception occurred:", type(e).__name__)
            print("Exception details:", str(e))
            sio.emit(clientSID, "Error")
            
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


#=======================================================================
# Function to update saved data.json in every 12AM (midnight)
# This is used to make sure data in this device is always same as blockchain
#=======================================================================
# Define a function to check if the current time is between 23:55 and 00:05
# this is used to ignore any incoming message at submit.
def is_midnight_window():
    current_time = time.localtime()
    return (current_time.tm_hour == 23 and 55 <= current_time.tm_min <= 59) or (current_time.tm_hour == 0 and current_time.tm_min <= 5)

# Function below used to update data.json from blockchain index at midnight
def midnight_update():
    while True:
        current_time = time.localtime()
        
        # Check if the current time is 12:00 AM (midnight)
        if current_time.tm_hour == 0 and current_time.tm_min == 0:
            fetched_data = []
            fetched_data = get_valid_msg()
            with open(blockchain_index_json_path, 'w') as json_file:
                json.dump(fetched_data, json_file, indent=4)
            
            print('Midnight Update : Successfully copy all valid message from blockchain index')
        
        # Sleep for a while to avoid using excessive CPU
        eventlet.sleep(60)  # Sleep for 60 seconds (1 minute)

eventlet.spawn(midnight_update)

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
    
    # Check if it's within the midnight window (23:55 - 00:05)
    if is_midnight_window():
        print("Skipping 'submit' event processing during midnight window.")
        return
    
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
    
    # Copy all blockchain message from index to ./home/<machine_name>/.road-inspect-core
    print('Synchronization process')
    print('Index : ' + road_inspect_index)
    main_json = []
    main_json = get_valid_msg()
    with open(blockchain_index_json_path, 'w') as json_file:
        json.dump(main_json, json_file, indent=4)
    print('Successfully copy all valid message from blockchain index')

    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        eventlet.wsgi.server(eventlet.wrap_ssl(eventlet.listen(('0.0.0.0', 8443)),certfile=ssl_cert,keyfile=ssl_key,server_side=True), app)
    else:
        eventlet.wsgi.server(eventlet.listen(('0.0.0.0', 8765)), app)

