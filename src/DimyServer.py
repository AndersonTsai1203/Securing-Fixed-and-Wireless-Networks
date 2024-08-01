import pickle
import socket
import threading
from BloomFilter import BloomFilter

# Server address
SERVER_IP = '127.0.0.1'
SERVER_PORT = 55000

# List of CBFs
cbf_list = []

# List to keep track of client connections
clients = []

def handle_client(client_socket):
    while True:
        try:
            # get the length of the object we are about to receive
            length = client_socket.recv(8)
            # turn it back into an int
            length = int(length.decode('utf-8'))

            # I keep this to determine if we've received everything or not
            full_length = length
            message = None

            # loop until we've zeroed out our length
            while length > 0:
                # only receive what we need
                # at a maximum of 128 bit chunks
                chunk_len = min(128, length)

                length -= chunk_len

                chunk = client_socket.recv(chunk_len)
                if message is None:
                    message = chunk
                else:
                    message = message + chunk

            while len(message) < full_length:
                chunk_len = min(128, full_length - len(message))
                chunk = client_socket.recv(chunk_len)
                message = message + chunk

            # now that we've received everything, we turn it back into a python object
            deserialized_message = pickle.loads(message)

            if deserialized_message["type"] == "cbf":
                print(f"Received CBF from client: {deserialized_message['data']}")
                cbf = deserialized_message["data"]
                cbf_list.append(cbf)
            if deserialized_message["type"] == "qbf":
                print(f"Received QBF from client: {deserialized_message['data']}")
                try:
                    for cbf in cbf_list:
                        if cbf.compare(deserialized_message["data"]):
                            print("Match") # Segment 10C
                            client_socket.send("Match".encode())
                        else:
                            print("No match") # Segment 10C
                            client_socket.send("No match".encode())
                except:
                    client_socket.send("No cbf".encode())
            if deserialized_message["type"] == "":
                continue
            if not deserialized_message:
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
