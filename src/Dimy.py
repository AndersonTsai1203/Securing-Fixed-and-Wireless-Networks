import socket
import threading
import time
import random
import hashlib
from BloomFilter import BloomFilter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Protocol.SecretSharing import Shamir
from subrosa import split_secret, recover_secret, Share
import keyboard
import pickle

# Constants
EID_INTERVAL = 15  # seconds
SHARE_INTERVAL = 3  # seconds
K = 3  # threshold
N = 5  # number of shares
BLOOM_FILTER_SIZE = 800000  # 100Kb = 800,000 bits
BLOOM_FILTER_HASHES = 3
DBF_INTERVAL = 90  # seconds
DBF_RETENTION = 6  # keep max 6 DBFs
QBF_INTERVAL = 540  # seconds (9 minutes)


class DimyNode:
    def __init__(self, server_ip, server_port):
        self.covid_positive = False
        self.first_qbf = True
        self.time_when_qbf_created = None
        self.reconstructed_ephid = None
        self.server_ip = server_ip
        self.server_port = server_port
        self.udp_port = 55001
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((self.server_ip, self.server_port))
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.private_key = 0
        self.ephemeral_id = 0 # in hexdecimal = public key
        self.ephemeral_id_hash = 0 # in hexdecimal
        self.secret_shares = [] # a list of shares in hexdecimal
        self.received_data = []
        self.received_shares = []
        self.received_hash = []
        self.used_shares = []
        self.reconstructed_ephemeral_id = 0
        self.reconstructed_ephemeral_id_hash = 0
        self.encounter_id = None
        self.dbf = None
        self.bloom_count = 0
        self.dbf_list = []
        self.qbf = None
        self.cbf = None
        self.first = True
        self.time_when_dbf_created = ''

    ### Functions ###
    def generate_ephemeral_id(self):  ### Task 1
        self.private_key = x25519.X25519PrivateKey.generate()
        public_key = self.private_key.public_key()
        self.ephemeral_id = public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PublicFormat.Raw).hex()
        print(f"Generated EphID in hexdecimal: {self.ephemeral_id}")  # each byte = two hexdecimal characters
        self.ephemeral_id_hash = hashlib.sha256(bytes.fromhex(self.ephemeral_id)).hexdigest()
        print(f"Generated EphID hash in hexdecimal: {self.ephemeral_id_hash}")

    def prepare_share_ephemeral_id(self):  ### Task 2
        ephemeral_id_bytes = bytes.fromhex(self.ephemeral_id)
        shares = split_secret(ephemeral_id_bytes, K, N)
        self.secret_shares = [bytes(share).hex() for share in shares]
        print(f"Secret share in hexdecimal: {self.secret_shares}")

    def secret_share_ephemeral_id(self):  ### Combine Task 1 and Task 2
        self.generate_ephemeral_id()
        self.prepare_share_ephemeral_id()
        threading.Timer(EID_INTERVAL, self.secret_share_ephemeral_id).start()

    def broadcast_secret_shares(self):  ### Task 3
        sock = self.udp_socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            for index in range(len(self.secret_shares)):
                probability = random.uniform(0, 1)
                if probability < 0.5:
                    time.sleep(SHARE_INTERVAL)
                    continue
                else:
                    message = f"{self.secret_shares[index] + self.ephemeral_id_hash}"
                    sock.sendto(message.encode(), ('<broadcast>', self.udp_port))
                    print(f"Broadcasted message: {self.secret_shares[index] + self.ephemeral_id_hash}")
                    time.sleep(SHARE_INTERVAL)

    def receive_secret_shares(self):  ### Task 4 - combine part a, b, c
        sock = self.udp_socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', self.udp_port))
        while True:
            data, _ = sock.recvfrom(1024)
            message = data.decode()
            received_secret_share = message[:70]
            received_secret_hash = message[70:]
            if received_secret_hash == self.ephemeral_id_hash:
                continue
            else:
                print(f"Received secret share: {received_secret_share}")
                print(f"Received hash: {received_secret_hash}")
                timestamp = time.time()
                self.received_data.append((received_secret_share, received_secret_hash, timestamp))
                if self.can_reconstruct_ephid():
                    self.reconstruct_ephemeral_id()

    def clear_used_shares(self):  ### Task 4 - part a
        for used_share in self.used_shares:
            self.received_shares.remove(used_share)

    # This function checks if there are at least 3 shares with the same hash part
    # and if the time span between the first and last of these shares is at least 9 seconds,
    # making it possible to reconstruct the EphID.
    def can_reconstruct_ephid(self):  ### Task 4 - part b
        hash_counts = {}
        for share, hash, timestamp in self.received_data:
            if hash not in hash_counts:
                hash_counts[hash] = []
            hash_counts[hash].append((share, timestamp))
            
        for hash, shares in hash_counts.items():
            if len(shares) >= 3:
                timestamps = [timestamp for _, timestamp in shares]
                received_shares = [share for share, _ in shares]
                if max(timestamps) - min(timestamps) >= 9:
                    self.received_hash = hash
                    self.received_shares = received_shares
                    self.used_shares = received_shares
                    return True
        return False

    def reconstruct_ephemeral_id(self):  ### Task 4 - part c
        # Show nodes attempting reconstruction of EphID
        print("Attempting to reconstruct EphID from received shares...")
        # Collect at least 3 shares with matching same EphID hash
        if len(self.received_shares) >= K:
            # Reconstruct EphID from shares
            binary_shares = [bytes.fromhex(share) for share in self.received_shares]
            shares = [Share.from_bytes(share) for share in binary_shares]
            self.reconstructed_ephid = recover_secret(shares[:K])
            self.reconstructed_ephemeral_id = self.reconstructed_ephid.hex()
            reconstructed_ephid_hash = hashlib.sha256(self.reconstructed_ephid).hexdigest()
            print(f"Reconstructed EphID: {self.reconstructed_ephemeral_id}")
            if reconstructed_ephid_hash == self.received_hash:
                print(f"Verification successful")
                self.clear_used_shares()
                self.perform_ecdh()
                return
            else:
                print(f"Verification failed")
        else:
            print("Insufficient number of shares to reconstruct EphID...")
            return
        
    def perform_ecdh(self):  ### Task 5
        # Generate a shared key (an Encounter ID)
        self.encounter_id = self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(self.reconstructed_ephid))
        # Show nodes have generated an Encounter ID
        print(f"Generated EncID: {self.encounter_id.hex()}")
        # Create a new bloom filter if required
        self.create_dbf()
        # Encode EncID into the Daily Bloom Filter
        self.add_encounter_id()
        # Create and send daily Query Bloom Filter
        self.create_and_send_qbf()

    def can_create_new_dbf(self):  ### Task 7
        time_elapsed = time.time() - self.time_when_dbf_created
        if time_elapsed >= 20: ##needs to be 90
            return True
        return False

    def create_dbf(self):  ### Task 6
        if self.first:
            self.dbf = BloomFilter(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES)
            self.time_when_dbf_created = time.time()
            print("New Daily Bloom Filter created.")
            self.first = False
        elif self.can_create_new_dbf():
            self.dbf_list.append(self.dbf)
            self.create_qbf()
            self.dbf = BloomFilter(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES)
            self.bloom_count = 0
            print("New Daily Bloom Filter created.")

    def add_encounter_id(self):  ### Task 6
        self.dbf.add(self.encounter_id)
        # Print number of encounter IDs that have been encoded in bloom filter
        self.bloom_count += 1
        print(f"Number of EncId encoded in bloom filter: {self.bloom_count}")
        # Print number of non-zero bits to demonstrate that EncIDs are being encoded into the bloom filter
        self.dbf.bits_non_zero()
        # Delete Encounter ID
        self.encounter_id = None

    def can_create_new_qbf(self):  ### Task 8
        if self.time_when_qbf_created is None:
            time_elapsed = time.time() - self.time_when_dbf_created
            if time_elapsed >= 30:  ##needs to be 540
                return True
        else:
            time_elapsed = time.time() - self.time_when_qbf_created
            if time_elapsed >= 30:  ##needs to be 540
                return True
        return False

    def create_qbf(self): ## Task 8
        # Check if there are six Daily Bloom Filters in the dbf_list
        if self.can_create_new_qbf():
            # If so create a new Query Bloom Filter
            self.qbf = BloomFilter(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES)
            for dbf in self.dbf_list:
                self.qbf.add(dbf.to_bytes())
    
    def send_qbf_to_server(self):  ## Task 9
        if self.qbf is None:
            print("No QBF to send.")
            return
        qbf_data = {"type": 'qbf', "data": self.qbf}
        qbf_package = pickle.dumps(qbf_data)

        # get the length of the pickled object
        length = len(qbf_package)
        # convert into a fixed width string
        length = str(length).rjust(8, '0')
        # send the length of the object we will send
        self.tcp_socket.sendall(bytes(length, 'utf-8'))
        # send the object
        self.tcp_socket.sendall(qbf_package)

        response = self.tcp_socket.recv(1024)
        print(f"Server response for QBF: {response.decode()}")

    def create_and_send_qbf(self):  ## Task 9
        if self.covid_positive:
            print("Covid positive. QBFs will cease to be sent.")
            return
        self.create_qbf()
        self.send_qbf_to_server()

    def create_cbf(self):  ## Task 10
        self.cbf = BloomFilter(BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES)
        for dbf in self.dbf_list:
            self.cbf.add(dbf.to_bytes())

    def send_cbf_to_server(self):  ## Task 10
        if self.cbf is None:
            print("No CBF to send.")
            return
        cbf_data = {"type": 'cbf', "data": self.cbf}
        cbf_package = pickle.dumps(cbf_data)
        # get the length of the pickled object
        length = len(cbf_package)
        # convert into a fixed width string
        length = str(length).rjust(8, '0')
        # send the length of the object we will send
        self.tcp_socket.sendall(bytes(length, 'utf-8'))
        # send the object
        self.tcp_socket.sendall(cbf_package)
        response = self.tcp_socket.recv(1024)
        print(f"Server response for CBF: {response.decode()}")
        # Set covid positive to true and stop sending QBFs
        if response.decode() == 'Match':
            self.covid_positive = True

    def create_and_send_cbf(self):  ## Task 10
        while True:
            if keyboard.is_pressed('c'):
                print('Covid detected')
                self.create_cbf()
                self.send_cbf_to_server()

    
    def run(self):
        threading.Thread(target=self.secret_share_ephemeral_id).start()
        threading.Thread(target=self.broadcast_secret_shares).start()
        threading.Thread(target=self.receive_secret_shares).start()
        threading.Thread(target=self.create_and_send_cbf()).start()
        while True:
            time.sleep(1)

if __name__ == "__main__":
    client = DimyNode("127.0.0.1", 55000)
    client.run()
