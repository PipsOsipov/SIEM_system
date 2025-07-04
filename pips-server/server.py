import socket
import yaml
import threading
import re
import psycopg2
from datetime import datetime

with open('server_conf.yml', 'r') as f:
    data = yaml.safe_load(f)
    
    if 'settings' in data and isinstance(data['settings'], dict):
        ADDRESS = data['settings'].get('address')
        PORT = data['settings'].get('port')
        print (ADDRESS, PORT)
    else:
        print("Error: server_conf.yml 'settings' error.")
        
    if 'database' in data and isinstance(data['database'], dict):
        DB_NAME = data['database'].get('db_name')
        DB_USER = data['database'].get('user')
        DB_PASSWORD = data['database'].get('password')
        DB_HOST = data['database'].get('host')
        DB_PORT = data['database'].get('port')
        print(f"database {DB_NAME} must be on {DB_HOST}:{DB_PORT}")
    else:
        print("Error: server_conf.yml 'database' error.")
     
db_connect = psycopg2.connect(database=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
db_cursor = db_connect.cursor()
     
def handle_client(connect, addr):
    print(f"Client connected: {addr}")
    buffer = ""
    while True:
        try:
            datablock = connect.recv(BUFFER_SIZE)
            if not datablock:
                print(f"Client {addr} disconnected")
                break

            buffer += datablock.decode('utf-8')
            # print("BUFFER_TYPE:", type(buffer))
            # print("BUFFER_CONTENT", repr(buffer))

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                # print("BUFFER_TYPE:", type(buffer))
                # print("LINE_TYPE:", type(line))
                # print("BUFFER_CONTENT", repr(buffer))
                line = line.strip()
                if line:
                    # print(line)
                    # print("Line type:", type(line))
                    parse_log(line)
            connect.sendall(datablock)
        except ConnectionResetError:
            print(f"Client {addr} disconnected")
            break
        except Exception as e:
            print(f"Error on a client side {addr}: {e}")
            break
    connect.close()
     
     
def parse_log(log_line):
    for tag, parser in PARSERS.items():
        if log_line.startswith(tag):
            parser(log_line)
            return
    else:
        print("Unlnown log")
   
def parse_ssh_log(log_line):
    password_match = SSH_PASSWORD_PATTERN.match(log_line)
    session_match = SSH_SESSION_PATTERN.match(log_line)

    if password_match:
        processed_line = password_match.groupdict()
        processed_line['timestamp'] = datetime.fromisoformat(processed_line['timestamp'])
        db_cursor.execute(
            """ INSERT INTO ssh_access_log (timestamp, status, client_ip, user_name) VALUES (%s, %s, %s, %s)""",
            (processed_line['timestamp'],
                  processed_line['status'],
                  processed_line['ip'],
                  processed_line['user']))
        db_connect.commit()
        print(f"timestamp: {processed_line['timestamp']}| Access status: {processed_line['status']}| Client_ip: {processed_line['ip']}| User: {processed_line['user']}")
        
    elif session_match:
        processed_sline = session_match.groupdict()
        processed_sline['timestamp'] = datetime.fromisoformat(processed_sline['timestamp'])
        db_cursor.execute(
            """ INSERT INTO ssh_session_log (timestamp, host_name, session_status, user_name) VALUES (%s, %s, %s, %s)""",
            (processed_sline['timestamp'],
             processed_sline['host'],
             processed_sline['status'],
             processed_sline['user']))
        db_connect.commit()
        print(f"timestamp: {processed_sline['timestamp']}| host_name: {processed_sline['host']}| Session status: {processed_sline['status']}| User: {processed_sline['user']}")
    else:
        print(f"Unknown str: {log_line}")

def parse_squid_log(log_line):
    squid_match = SQUID_PATTERN.match(log_line)

    if squid_match:
        processed_line = squid_match.groupdict()
        processed_line['timestamp'] = datetime.fromtimestamp(float(processed_line['timestamp']))
        db_cursor.execute(
            """ INSERT INTO squid_log (timestamp, client_ip, status_code, method, url_port, squid_user, type, dst_host) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (processed_line['timestamp'],
             processed_line['client_ip'],
             processed_line['status_code'],
             processed_line['method'],
             processed_line['url_port'],
             processed_line['squid_user'],
             processed_line['type'],
             processed_line['dst_host']))
        db_connect.commit()
        print(f"Timestamp: {processed_line['timestamp']}| Client ip: {processed_line['client_ip']}| Status_code: {processed_line['status_code']} | Method: {processed_line['method']}|| Url_port: {processed_line['url_port']} Squid_user: {processed_line['squid_user']}| Type: {processed_line['type']}| Dst_host: {processed_line['dst_host']}")
    else:
        print(f"Unknown str: {log_line}")

def parse_usb_log(log_line):
    usb_match = USB_PATTERN.match(log_line)
    if usb_match:
        processed_line = usb_match.groupdict()
        processed_line['timestamp'] = datetime.fromisoformat(processed_line['timestamp'])
        db_cursor.execute(
            """ INSERT INTO usb_log (timestamp, host_name, usb_port, message) VALUES (%s, %s, %s, %s)""",
            (processed_line['timestamp'],
             processed_line['host'],
             processed_line['usb_port'],
             processed_line['message']))
        db_connect.commit()
        print(f"timestamp: {processed_line['timestamp']}| host_name: {processed_line['host']}| usb_port: {processed_line['usb_port']}| message: {processed_line['message']}")
    else:
        print(f"Unknown str: {log_line}")

def parse_vpn_log(log_line):
    vpn_match = VPN_PATTERN.match(log_line)

    if vpn_match:
        processed_line = vpn_match.groupdict()
        processed_line['timestamp'] = datetime.fromisoformat(processed_line['timestamp'])
        db_cursor.execute(
            """ INSERT INTO vpn_log (timestamp, host_name, service, message) VALUES (%s, %s, %s, %s)""",
            (processed_line['timestamp'],
             processed_line['host'],
             processed_line['service'],
             processed_line['message']))
        db_connect.commit()
        print(f"timestamp: {processed_line['timestamp']}| host_name: {processed_line['host']}| service: {processed_line['service']}|  message: {processed_line['message']}")
    else:
        print(f"Unknown str: {log_line}")

PARSERS = {
    "[ssh]": parse_ssh_log,
    "[squid]": parse_squid_log,
    "[vpn]": parse_vpn_log,
    "[usb]":parse_usb_log,
    }

USB_PATTERN = re.compile('^\[usb\](?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+(?P<host>\S+)\s+kernel:\s+\[\s*\d+\.\d+\]\s+usb\s+(?P<usb_port>\S+):\s+(?P<message>.+)$')
VPN_PATTERN = re.compile(r'^\[vpn\](?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+(?P<host>\S+)\s+(?P<service>\S+)\[\d+\]:\s+(?P<message>.+)$')
SSH_PASSWORD_PATTERN = re.compile(r'\[ssh\](?P<timestamp>[\d\-T:\.+]+)\s+(?P<host>\S+)\s+\S+\[\d+\]:\s+(?P<status>(?:Accepted|Failed)\s+password)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)\s+\w+')
SSH_SESSION_PATTERN = re.compile(r'\[ssh\](?P<timestamp>[\d\-T:\.+]+)\s+(?P<host>\S+)\s+\S+\[\d+\]:\s+pam_unix\(sshd:session\):\s+(?P<status>session\s+(?:opened|closed))\s+for\s+user\s+(?P<user>\w+)')
SQUID_PATTERN = re.compile(r'^\[squid\](?P<timestamp>[\d.]+)\s+(?P<processing>\d+)\s+(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<status_code>\w+/\d+)\s+(?P<bytes>\d+)\s+(?P<method>\w+)\s+(?P<url_port>(?:[a-zA-Z0-9._-]+|\d{1,3}(?:\.\d{1,3}){3}):\d+)\s+(?P<squid_user>\w+)\s+(?P<type>[A-Z_]+)\/(?P<dst_host>(?:\-|\d{1,3}(?:\.\d{1,3}){3}))\s+(?P<ident>\S+)$')

BUFFER_SIZE = 1024

def start_tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((ADDRESS, int(PORT)))
        server.listen()
        print(f"Listening {ADDRESS}:{PORT} ...")

        while True:
            try:
                connect, addr = server.accept()
                client_handler = threading.Thread(target=handle_client, args=(connect, addr))
                client_handler.start()
            except Exception as e:
                print(f"Connection error: {e}")
                continue

if __name__ == "__main__":
    start_tcp_server()
        