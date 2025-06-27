import socket
import yaml
import threading
import re

with open('server_conf.yml', 'r') as f:
    data = yaml.safe_load(f)
    
    if 'settings' in data and isinstance(data['settings'], dict):
        ADDRESS = data['settings'].get('address')
        PORT = data['settings'].get('port')
        print (ADDRESS, PORT)
    else:
        print("Error: server_conf.yml 'settings' error.")
     
SSH_PASSWORD_PATTERN = re.compile(r'\[ssh\] (?P<timestamp>[\d\-T:\.+]+) (?P<host>\S+) \S+\[\d+\]: (?P<status>(?:Accepted|Failed) password) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
SSH_SESSION_PATTERN = re.compile(r'\[ssh\] (?P<timestamp>[\d\-T:\.+]+) (?P<host>\S+) \S+\[\d+\]: pam_unix\(sshd:session\): (?P<status>session (?:opened|closed)) for user (?P<user>\w+)')        
SQUID_PATTERN = re.compile(r'\[squid\]\s+(?P<timestamp>[\d.]+)\s+(?P<processing>\d+)\s+(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<status_code>\w+/\d+)\s+(?P<bytes>\d+)\s+(?P<method>\w+)\s+(?P<url_port>(?:[a-zA-Z0-9._-]+|\d{1,3}(?:\.\d{1,3}){3}):\d+)\s+(?P<squid_user>\w+)\s+(?P<type>[A-Z_]+)\/(?P<dst_host>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<ident>\S+)')
BUFFER_SIZE = 1024

def handle_client(connect, addr):
    print(f"Client connected: {addr}")
    while True:
        try:
            datablock = connect.recv(BUFFER_SIZE)
            valid_data = datablock.decode('utf-8')
            #parse_ssh_log(valid_data)
            parse_squid_log(valid_data)
            
            #print ("Good: " + valid_data)
            
            if not datablock:
                print(f"Client {addr} disconnected")
                break
            connect.sendall(datablock)
        except ConnectionResetError:
            print(f"Client {addr} disconnected")
            break
        except Exception as e:
            print(f"Error on a client side {addr}: {e}")
            break
    connect.close()
        
def parse_ssh_log(log_line):
    password_match = SSH_PASSWORD_PATTERN.match(log_line)
    session_match = SSH_SESSION_PATTERN.match(log_line)

    if password_match:
        processed_line = password_match.groupdict()
        print(f"timestamp: {processed_line['timestamp']}| host_name: {processed_line['host']}| Access status: {processed_line['status']}| User: {processed_line['user']}")
        return
    elif session_match:
        processed_line = session_match.groupdict()
        print(f"timestamp: {processed_line['timestamp']}| host_name: {processed_line['host']}| Session status: {processed_line['status']}| User: {processed_line['user']}")
        return
    else:
        print(f"Unknown str: {log_line}")

def parse_squid_log(log_line):
    squid_match = SQUID_PATTERN.match(log_line)

    if squid_match:
        processed_line = squid_match.groupdict()
        print(f"Timestamp: {processed_line['timestamp']}| Client ip: {processed_line['client_ip']}| Status_code: {processed_line['status_code']} | Method: {processed_line['method']}|| Url_port: {processed_line['url_port']} Squid_user: {processed_line['squid_user']}| Type: {processed_line['type']}| Dst_host: {processed_line['dst_host']}")
    else:
        print(f"Unknown str: {log_line}")

# def parse_usb_log(log_line):
#     print (log_line)
#
# def pase_vpn_log(log_line):
#     print (log_line)
        

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
        