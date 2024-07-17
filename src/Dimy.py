import socket
import threading
import sys
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Protocol.SecretSharing import Shamir
import random

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
K = 3 # threshold
N = 5 # number of shares
UDP_PORT = 5000
TCP_PORT = 55000
BLOOM_FILTER_SIZE = 100000
BLOOM_FILTER_HASHES = 3
DBF_INTERVAL = 90  # seconds
DBF_RETENTION = 6  # keep max 6 DBFs
QBF_INTERVAL = 540  # seconds (9 minutes)

# Global variables
node_id = random.randint(0, 1000)
ephemeral_id = None
secret_shares = None
server_ip = "127.0.0.1"

### Functions ###
def generate_ephemeral_id(): ### Task 1
    global ephemeral_id
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    ephemeral_id = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    print(f"Generated EphID in hexdecimal: {ephemeral_id}") # each byte = two hexdecimal characters

def prepare_share_ephemeral_id(): ### Task 2
    global secret_shares_part1, secret_shares_part2
    share_part1 = ephemeral_id[:32] # first 32 characters
    share_part2 = ephemeral_id[32:] # last 32 characters
    shares1 = Shamir.split(K, N, bytes.fromhex(share_part1))
    shares2 = Shamir.split(K, N, bytes.fromhex(share_part2))
    secret_shares_part1 = [(i, share.hex()) for i, share in shares1]
    secret_shares_part2 = [(i, share.hex()) for i, share in shares2]
    print(f"Secret share part 1: {secret_shares_part1}")
    print(f"Secret share part 2: {secret_shares_part2}")  
    random_share =random.randint(0, 4)
    secret_shares = secret_shares_part1[random_share][1] + secret_shares_part2[random_share][1]
    print(f"Secret share in hexdecimal: {secret_shares}")
    
def secret_share_ephemeral_id(): ### Combine Task 1 and Task 2
    generate_ephemeral_id()
    prepare_share_ephemeral_id()
    threading.Timer(EID_INTERVAL, secret_share_ephemeral_id).start()

def broadcast_secret_shares(): ### Task 3
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        if random.random() < 0.5:
            continue
        message = f"Secret share: {secret_shares}"
        sock.sendto(message.encode(), ('<broadcast>', UDP_PORT))
        print(f"Broadcasted shares: {secret_shares}")
        time.sleep(SHARE_INTERVAL)

def receive_secret_shares(): ### Task 4
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', UDP_PORT))
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"Received secret share: {data.decode()}")
        time.sleep(SHARE_INTERVAL)

def tcp_connection():
    while True:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to server: {SERVER_IP} : {SERVER_PORT}")
        message = input("")
        tcp_socket.send(message.encode())
        response = tcp_socket.recv(1024).decode()
        print(f"Received from server: {response}")
        tcp_socket.close()

if __name__ == "__main__":
    threading.Thread(target=tcp_connection).start()
    secret_share_ephemeral_id()
    while True:
        time.sleep(1)

