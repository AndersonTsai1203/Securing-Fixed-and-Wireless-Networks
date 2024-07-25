import socket
import threading
import multiprocessing
import sys
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Protocol.SecretSharing import Shamir
import random

# Constants
EID_INTERVAL = 15  # seconds
SHARE_INTERVAL = 3  # seconds
K = 3 # threshold
N = 5 # number of shares
BLOOM_FILTER_SIZE = 100000
BLOOM_FILTER_HASHES = 3
DBF_INTERVAL = 90  # seconds
DBF_RETENTION = 6  # keep max 6 DBFs
QBF_INTERVAL = 540  # seconds (9 minutes)

class DimyNode:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.udp_port = 55001
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_ip, self.server_port))
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.ephemeral_id = None
        self.secret_shares = None
    
    ### Functions ###
    def generate_ephemeral_id(self): ### Task 1
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.ephemeral_id = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        print(f"Generated EphID in hexdecimal: {self.ephemeral_id}") # each byte = two hexdecimal characters
    
    def prepare_share_ephemeral_id(self): ### Task 2
        share_part1 = self.ephemeral_id[:32] # first 32 characters
        share_part2 = self.ephemeral_id[32:] # last 32 characters
        shares1 = Shamir.split(K, N, bytes.fromhex(share_part1))
        shares2 = Shamir.split(K, N, bytes.fromhex(share_part2))
        secret_shares_part1 = [(i, share.hex()) for i, share in shares1]
        secret_shares_part2 = [(i, share.hex()) for i, share in shares2]
        self.secret_shares = [(i, share1 + share2) for (i, share1), (_, share2) in zip(secret_shares_part1, secret_shares_part2)]
        print(f"Secret share in hexdecimal: {self.secret_shares}")

    def secret_share_ephemeral_id(self): ### Combine Task 1 and Task 2
        self.generate_ephemeral_id()
        self.prepare_share_ephemeral_id()
        threading.Timer(EID_INTERVAL, self.secret_share_ephemeral_id).start()

    def broadcast_secret_shares(self): ### Task 3
        sock = self.udp_socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            if random.random() < 0.5:
                continue
            if self.secret_shares is None:
                continue
            index = random.randint(0, len(self.secret_shares) - 1)
            message = f"Secret share: {self.secret_shares[index][1]}"
            sock.sendto(message.encode(), ('<broadcast>', self.udp_port))
            print(f"Broadcasted shares: {self.secret_shares}")
            time.sleep(SHARE_INTERVAL)

    def receive_secret_shares(self): ### Task 4
        sock = self.udp_socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', self.udp_port))
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"Received secret share: {data.decode()}")
            time.sleep(SHARE_INTERVAL)

    def run(self):
        threading.Thread(target=self.secret_share_ephemeral_id).start()
        threading.Thread(target=self.broadcast_secret_shares).start()
        threading.Thread(target=self.receive_secret_shares).start()
        while True:
            time.sleep(1)
    
if __name__ == "__main__":
    client = DimyNode("127.0.0.1", 55000)
    client.run()
