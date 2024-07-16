import socket
import threading
import sys
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Protocol.SecretSharing import Shamir

### Global variables ###
# Server details
SERVER_IP = sys.argv[1]
SERVER_PORT = int(sys.argv[2])

# UDP Broadcast details
BROADCAST_IP = '255.255.255.255'
BROADCAST_PORT = 50000

# Constants
EID_INTERVAL = 15  # seconds
SHARE_INTERVAL = 3  # seconds
K = 3
N = 5
UDP_PORT = 5000
TCP_PORT = 55000
BLOOM_FILTER_SIZE = 100000
BLOOM_FILTER_HASHES = 3
DBF_INTERVAL = 90  # seconds
DBF_RETENTION = 6  # keep max 6 DBFs
QBF_INTERVAL = 540  # seconds (9 minutes)

# Global variables
ephemeral_id = None
server_ip = "127.0.0.1"

### Functions ###
def generate_ephemeral_id(): ### Task 1
    global ephemeral_id
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    ephemeral_id = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(f"Generated EphID in byte string: {ephemeral_id}")

def share_ephemeral_id(): ### Task 2
    global secret_shares
    shares = Shamir.split(K, N, ephemeral_id.encode())
    secret_shares = [(i, share.hex()) for i, share in shares]
    print(f"Generated shares: {secret_shares}")

def udp_broadcast():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = b"Hello from client"
    while True:
        udp_socket.sendto(message, (BROADCAST_IP, BROADCAST_PORT))
        print(f"Broadcasting message: {message.decode()}")
        threading.Event().wait(5)

def tcp_connection():
    while True:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect((SERVER_IP, SERVER_PORT))
        message = input("Enter message to send to server: ")
        tcp_socket.send(message.encode())
        response = tcp_socket.recv(1024).decode()
        print(f"Received from server: {response}")
        tcp_socket.close()

if __name__ == "__main__":
    threading.Thread(target=tcp_connection).start()
    while True:
        generate_ephemeral_id()
        time.sleep(EID_INTERVAL)

