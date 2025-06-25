import socket
import yaml
import threading


with open('server_conf.yml', 'r') as f:
    data = yaml.safe_load(f)
    
    if 'settings' in data and isinstance(data['settings'], dict):
        ADDRESS = data['settings'].get('address')
        PORT = data['settings'].get('port')
        print (ADDRESS, PORT)
    else:
        print("Error: server_conf.yml 'settings' error.")
        
BUFFER_SIZE = 1024

def handle_client(connect, addr):
    print(f"Client connected: {addr}")
    while True:
        try:
            datablock = connect.recv(BUFFER_SIZE)
            data = datablock.decode('utf-8')
            print (data)
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
        