<!-- Title -->
<span align = "center">

# Road Inspect Core

</span>
<!-- End of Title -->

<!--
<br>
<span align = "center">
   
![Logo](https://github.com/SuryaAssistant/iota-raspberrypi-gateway/blob/main/new_iota.png)

</span>
<br>
-->

Core program of <b>road-inspect</b>, blockchain-based system for report and monitoring road quality. 
Built on top of python IOTA.rs client library and [iota-websocket](https://github.com/SuryaAssistant/iota-websocket). 
As default, this code work on `Chrysalis Devnet`. 
If you want to use in production, please install hornet or collaborate with someone who has a hornet API to Chrysalis Mainnet.

For front-end demo, please go to [road inspect](https://github.com/SuryaAssistant/road-inspect) or [dalankudus](http://dalankudus.xyz).

## Tested System
- VPS x86_64
  - 2 Core CPU
  - 2 GB of RAM
  - 20 GB of Disk
- Raspberry Pi 3B+
  - We also test on raspberry pi, but we are not recommending you to use raspberry pi 3B+. Because IOTA Tangle also use a small amount of proof of work (POW).

## Prequerities
- Python 3.x (Python 3.10 is recommended)
- pip

## Install Required Dependency

- Socketio
```
pip install python-socketio
```

- Eventlet
```
pip install eventlet
```

- Starkbank ECDSA
```
pip install starkbank-ecdsa
```

- Pysha
```
pip install pysha3
```

## Running on Your System
- Open terminal and clone this repository
```
git clone https://github.com/SuryaAssistant/road-inspect-core
```

- For x86_64 system (64-bit), go to `x86_64` 
```
cd road-inspect-core/x86_64
```

- Run program 
```
python3 main.py
```

## Websocket Emit Syntax
|Feature|Syntax|
|---|---|
| Upload data to IOTA Tangle | `data/{<data>}/<return_sid>/<specified_tag>`|
| Get unfinished report (show where damaged road that still not maintained) | `resume/<tag_index>/<return_sid>` |
| Get detail information of report ticket and other linked ticket | `ticket/<msg_id>/<return_sid>` |
| Get system core public key in PEM format. Used for user that want to use external ECDSA verification | `convert_to_pem/<compressed_public_key>/<return_sid>` |


## Digital Signature for Data Integrity
This project used `secp256k1` elliptic curve to generate private key and public key. 
We are using python [starkbank-ecdsa](https://github.com/starkbank/ecdsa-python) library to generate and validate digital signature for the data. 
When you run the `main.py` for the first time, it will generate private key automatically and store the private key. 
As long as not re-installed, private key will still remain there. 
Please get a backup of generated private key.

Road inspect core save all report data on the same IOTA Tangle Index (next, we call it as `blockchain_index`). 
System will differentiate message that from this device or not by using ECDSA verification so it is important to keep private key when you are using different machine. 
Only valid data that from this device is used for front-end process.

For example of how ECDSA verification works, please read [here](https://github.com/SuryaAssistant/iota-websocket/tree/main#digital-signature-for-data-integrity)


## Automatic Start Up with Systemmd
You can also make this script always running when your machine is starting up. Please follow steps below:

- Create road-inpect-core.service
  ```
  sudo nano /etc/systemd/system/road-inspect-core.service
  ```

- Please change `<your_machine_name>` with your machine name and `<python_version>` with python3 that you are using, for example `python3.10`.
   ```
   [Unit]
   Description=Road Inspect Core Program
   After=network.target
   
   [Service]
   User=<your_machine_name>
   WorkingDirectory=/home/<your_machine_name>
   ExecStart=/usr/bin/python3 /home/<your_machine_name>/road-inspect-core/x86_64/main.py
   Restart=always
   Environment="PYTHONPATH=$PYTHONPATH:/home/<your_machine_name>/.local/lib/<python_version>/site-packages"
   
   [Install]
   WantedBy=multi-user.target
   ```
   
- Save using `CTRL+X`, followed by `Y` and `Enter`
  
- Reload daemon in terminal
  ```
  sudo systemctl daemon-reload
  ```
  
- Enable service
  ```
  sudo systemctl enable road-inspect-core.service
  ```
  
- Start road-inspect-core
  ```
  sudo systemctl start road-inspect-core.service
  ```

## Production 
Before use this code for production, please note several things.
1. This code mainly used in IOTA Chrysalis Devnet Network.
   To use public stable IOTA Mainnet, please consider to change `chrysalis_url` in `x86_64/config/config.py`.
   Please change this value with hornet node url that connect with IOTA Mainnet.
   ```
   sudo nano /road-inspect-core/x86_64/config/config.py
   ```
   
2. Define your `blockchain_index`.
   This is where your road inspect core data is saved on IOTA Tangle.
   You can make it as `1234567890` or `abcdefghijklmn`, but random 64 character is better.
   If you have defined your own `blockchain_index`, please change the value of `blockchain_index` in `config.py`
   ```
   sudo nano /road-inspect-core/x86_64/config/config.py
   ```
   
3. Websocket is run on `ws://` or `http://`.
   When you send data from websocket to `https://` website, it will considered as `mixed content` and browser will not process websocket communication.
   Upgrading from websocket to websocket secure or `wss://` is the way that you can connect your `https://` website.

   Buy a domain and install a SSL for websocket

  

## Upgrade Websocket to Websocket Secure 
This step is adding SSL to websocket connection, so HTTPS website can connect with our websocket.

Before start, you need to have a domain, cheap domain is ok.

1. Install Nginx
   
   ```
   sudo apt-get update
   ```
   ```
   sudo apt-get install certbot python3-certbot-nginx nginx
   ```

   If there is error to install Nginx like unable to ..., please follow steps below.

   - Change download mirror
   ```
   sudo nano /etc/apt/sources.list
   ```
   - Change all mirror link to `deb http://archive.ubuntu.com/ubuntu ... `
   - Update system
   ```
   sudo apt-get update
   ```
   ```
   sudo apt-get upgrade
   ```

2. Update DNS in your domain management
   
   - A record ==> point to your IP address
   - CNAME ==> www point to your-domain.com
   - wait until you can ping your-domain.com
     
3. Configure Nginx

   Change `<your-domain.com>` with domain that you have prepared before (without `<` and `>`).

   - Create SSL certificate
   ```
   sudo certbot --nginx -d <your-domain.com>
   ```
   - Configure Nginx
   ```
   sudo nano /etc/nginx/sites-available/<your-domain.com>
   ```
   - Fill that file with
   ```
   server {
       listen 443 ssl;
       server_name <your-domain.com>;
   
       ssl_certificate /etc/letsencrypt/live/<your-domain.com>/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/<your-domain.com>/privkey.pem;
   
       location /socket.io {
           proxy_pass http://127.0.0.1:8443/socket.io;  # Updated to port 8443
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_set_header X-Forwarded-Host $host;
           proxy_set_header X-Forwarded-Port $server_port;
       }
   
       # Other server configuration, if needed
   }
   ```
   - Enable Nginx configuration
   ```
   sudo ln -s /etc/nginx/sites-available/<your-domain.com> /etc/nginx/sites-enabled/
   ```
   - Test Nginx
   ```
   sudo nginx -t
   ```
   - Restart Nginx
   ```
   sudo systemctl restart nginx
   ```
   
4. Configure firewall

   Please be cautious, it may block your SSH connection if not configured properly

   ```
   sudo ufw status
   ```
   Change `<your_ssh_port>` with port that you use for SSH connection. As default, it is `22`
   
   ```
   sudo ufw allow 443/tcp
   sudo ufw allow 8443
   sudo ufw allow <your_ssh_port>
   sudo ufw allow OpenSSH
   ```
   ```
   sudo ufw enable
   ```
   ```
   sudo ufw reload
   ```

5. If there is error like `permission denied` please follow steps below
   
   ```
   sudo chmod 755 /etc/letsencrypt/live/
   sudo chmod 755 /etc/letsencrypt/archive/
   ```
   ```
   sudo chown -R $USER /etc/letsencrypt/
   ```
