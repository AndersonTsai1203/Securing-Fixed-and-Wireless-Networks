import socket
import threading

# Server address
SERVER_IP = '127.0.0.1'
SERVER_PORT = 55000

# List to keep track of client connections
clients = []

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print(f"Received from client: {message}")
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
