import socket
import yaml
import time
import os
import threading

PROGRAM_LIST = []

with open('agent_conf.yml', 'r') as f:
    data = yaml.safe_load(f)
    
    if 'settings' in data and isinstance(data['settings'], dict):
        SERVER_ADDRESS = data['settings'].get('server_address')
        SERVER_PORT = data['settings'].get('server_port')
        if not SERVER_ADDRESS or not SERVER_PORT:
            raise ValueError("Error: Address or port is invalid.")
        print(f"OK: {SERVER_ADDRESS}:{SERVER_PORT}")
    else:
        raise ValueError("Error: agent_conf 'settings' error.")
    
    if 'logpath' in data and isinstance(data['logpath'], dict):
        LOGPATH_SSH = data['logpath'].get('ssh')
        LOGPATH_SQUID = data['logpath'].get('squid')
        LOGPATH_USB = data['logpath'].get('usb')
        LOGPATH_VPN = data['logpath'].get('vpn')
        if not LOGPATH_SSH and not LOGPATH_SQUID and not LOGPATH_USB and not LOGPATH_VPN:
            raise ValueError("Error: Failed logpath")
        print(f"OK: SSH = '{LOGPATH_SSH}', Squid = '{LOGPATH_SQUID}', USB = '{LOGPATH_USB}', VPN = '{LOGPATH_VPN}'")
    else:
        raise ValueError("Error: agent_conf 'logpath' error.")
    
    if 'program' in data and isinstance(data['program'], dict):
        SSH_NAME = data['program'].get('ssh_service')
        PROGRAM_LIST.append(SSH_NAME)
        SQUID_NAME = data['program'].get('squid_service')
        PROGRAM_LIST.append(SQUID_NAME)
        USB_NAME = data['program'].get('usb_service')
        PROGRAM_LIST.append(USB_NAME)
        VPN_NAME = data['program'].get('vpn_service')
        PROGRAM_LIST.append(VPN_NAME)
    print()
    print(PROGRAM_LIST)
    print()
    print(PROGRAM_LIST[0])
    print()

VPN_FILTER=["Preserving recently used remote address:","Attempting to establish TCP connection with", "process restarting","Initialization Sequence Completed"]
USB_FILTER=["New USB device found","USB disconnect", "Product:", "Manufacturer:", "SerialNumber:"]
SSH_FILTER=["Accepted password", "Failed password", "session opened", "session closed"]
BUFFER_SIZE = 1024
client_socket = None
socket_lock = threading.Lock()

def squid_log_reader(path):
    if not os.path.exists(path):
        print(f"Error: {path} not found")
        return
    try:
        with open(path, 'r') as squid_log:
            squid_log.seek(0, os.SEEK_END)     
            while True:
                line = squid_log.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                processed_line = line.strip()
                squid_line = PROGRAM_LIST[1] + processed_line
                print(squid_line)
                yield squid_line
    except KeyboardInterrupt:
        print()
    except Exception as e:
        print(f"Error: {e}")
        
def ssh_log_reader(path, filters):
    if not os.path.exists(path):
        print(f"Error: {path} not found")
        return
    try:
        with open(path, 'r') as ssh_log:
            ssh_log.seek(0, os.SEEK_END)     
            while True:
                line = ssh_log.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                processed_line = line.strip()
                if filters:
                    found = False
                    for f_line in filters:
                        if f_line in processed_line:
                            found = True
                            break
                    if found:
                        ssh_line = PROGRAM_LIST[0] + processed_line
                        print(ssh_line)
                        yield ssh_line
                else:
                    print(ssh_line)
                    yield ssh_line
    except KeyboardInterrupt:
        print()
    except Exception as e:
        print(f"Error: {e}")
        
def usb_log_reader(path, filters):
    if not os.path.exists(path):
        print(f"Error: {path} not found")
        return
    try:
        with open(path, 'r') as usb_log:
            usb_log.seek(0, os.SEEK_END)     
            while True:
                line = usb_log.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                processed_line = line.strip()
                if filters:
                    found = False
                    for f_line in filters:
                        if f_line in processed_line:
                            found = True
                            break
                    if found:
                        usb_line = PROGRAM_LIST[2] + processed_line
                        print(usb_line)
                        yield usb_line
                else:
                    print(usb_line)
                    yield usb_line
    except KeyboardInterrupt:
        print()
    except Exception as e:
        print(f"Error: {e}")

def vpn_log_reader(path, filters):
    if not os.path.exists(path):
        print(f"Error: {path} not found.")
        return
    try:
        with open(path, 'r') as vpn_log:
            vpn_log.seek(0, os.SEEK_END)     
            while True:
                line = vpn_log.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                processed_line = line.strip()
                if filters:
                    found = False
                    for f_line in filters:
                        if f_line in processed_line:
                            found = True

                            break
                    if found:
                        vpn_line = PROGRAM_LIST[3] + processed_line
                        print(vpn_line)
                        yield vpn_line
                else:
                    print(vpn_line)
                    yield vpn_line
    except KeyboardInterrupt:
        print()
    except Exception as e:
        print(f"Error: {e}")
    
def send_log_data(log_generator, log_type_name):
    global client_socket
    global socket_lock
    
    print(f"[{log_type_name} sending]...")
    for entry in log_generator:
        try:
            with socket_lock:
                if client_socket:
                    client_socket.sendall((entry + "\n").encode('utf-8'))
                else:
                    print(f"[{log_type_name}] Err. exit...")
                    break
        except BrokenPipeError:
            print(f"[{log_type_name} sender. exit from thread")
            break
        except Exception as e:
            print(f"[{log_type_name} sender. Error data transportig: {e}. Exit from thread.")
            break


def start_tcp_client():
    global client_socket
    try:
       client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       print(f"Attempting to connect to {SERVER_ADDRESS}:{SERVER_PORT}...")
       client_socket.connect((SERVER_ADDRESS, int(SERVER_PORT)))
       print(f"Connection status: OK")

       if LOGPATH_SSH:
            ssh_thread = threading.Thread(target=send_log_data, args=(ssh_log_reader(LOGPATH_SSH, SSH_FILTER), "SSH"))
            ssh_thread.daemon = True
            ssh_thread.start()
       
       if LOGPATH_SQUID:
            squid_thread = threading.Thread(target=send_log_data, args=(squid_log_reader(LOGPATH_SQUID), "Squid"))
            squid_thread.daemon = True
            squid_thread.start()
            
       if LOGPATH_USB:
           usb_thread = threading.Thread(target=send_log_data, args=(usb_log_reader(LOGPATH_USB, USB_FILTER), "USB"))
           usb_thread.daemon = True
           usb_thread.start()
       
       if LOGPATH_VPN:
           usb_thread = threading.Thread(target=send_log_data, args=(vpn_log_reader(LOGPATH_VPN, VPN_FILTER), "VPN"))
           usb_thread.daemon = True
           usb_thread.start()
       
       print("Client is running. Ctrl+C for exit")
        
       while True:
            time.sleep(1)
            
    except ConnectionRefusedError:
        print(f"Connection status: Failed. No server on {SERVER_ADDRESS}:{SERVER_PORT}")
    except TimeoutError:
        print(f"Time out: Cannot connect to {SERVER_ADDRESS}:{SERVER_PORT}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if client_socket:
            print("Client stopping...")
            client_socket.close()
        print("Client stoped...")
        
if __name__ == "__main__":
    start_tcp_client()        