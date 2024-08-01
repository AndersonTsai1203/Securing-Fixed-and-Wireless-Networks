import socket
import threading
from BloomFilter import BloomFilter

# Server address
SERVER_IP = '127.0.0.1'
SERVER_PORT = 55000
global cbf

# List to keep track of client connections
clients = []

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message.type == "cbf":
                print(f"Received CBF from client: {message.data}")
                global cbf
                cbf = message.data
            if message.type == "qbf":
                print(f"Received QBF from client: {message.data}")
                if cbf.check(message.data):
                    client_socket.send("Close contact detected".encode())
                else:
                    client_socket.send("No contact detected".encode())
            if message.type == "":
                continue
            if not message:
                break
            # print(f"Received from client: {message}")
            client_socket.send("Message received".encode())
        except ConnectionResetError:
            break
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_IP, SERVER_PORT))
    server.listen(5)
    print(f"Server started on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_socket, client_address = server.accept()
        print(f"Accepted connection from {client_address}")
        clients.append(client_socket)
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
