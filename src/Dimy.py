import socket
import threading
import time
import random
import hashlib
import BloomFilter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Protocol.SecretSharing import Shamir
from random import shuffle

# Constants
EID_INTERVAL = 15  # seconds
SHARE_INTERVAL = 3  # seconds
K = 3  # threshold
N = 5  # number of shares
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
        self.ephemeral_id_hash = None
        self.secret_shares = None
        self.received_shares = []
        self.encounter_ephid = None
        self.encounter_id = None

    ### Functions ###
    def generate_ephemeral_id(self):  ### Task 1
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.ephemeral_id = public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                    format=serialization.PublicFormat.Raw).hex()
        print(f"Generated EphID in hexdecimal: {self.ephemeral_id}") # each byte = two hexdecimal characters
        self.ephemeral_id_hash = hashlib.sha256(bytes.fromhex(self.ephemeral_id)).hexdigest()
        print(f"Generated EphID hash in hexdecimal: {self.ephemeral_id_hash}")
    
    def prepare_share_ephemeral_id(self): ### Task 2
        share_part1 = self.ephemeral_id[:32] # first 32 characters
        share_part2 = self.ephemeral_id[32:] # last 32 characters
        shares1 = Shamir.split(K, N, bytes.fromhex(share_part1))
        shares2 = Shamir.split(K, N, bytes.fromhex(share_part2))
        secret_shares_part1 = [(i, share.hex()) for i, share in shares1]
        secret_shares_part2 = [(i, share.hex()) for i, share in shares2]
        self.secret_shares = [(i, share1 + share2) for (i, share1), (_, share2) in
                              zip(secret_shares_part1, secret_shares_part2)]
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
                time.sleep(SHARE_INTERVAL)
                continue
            if self.secret_shares is not None and self.ephemeral_id_hash is not None:
                index = random.randint(0, N-1)
                message = f"{self.secret_shares[index][1] + self.ephemeral_id_hash}"
                sock.sendto(message.encode(), ('<broadcast>', self.udp_port))
                print(f"Broadcasted message: {self.secret_shares[index][1] + self.ephemeral_id_hash}")
                time.sleep(SHARE_INTERVAL)

    def receive_secret_shares(self): ### Task 4
        sock = self.udp_socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('', self.udp_port))
        while True:
            data, _ = sock.recvfrom(1024)
            message = data.decode()
            received_ephID = message[:64]
            received_ephID_hash = message[64:]
            print(f"Received EphID: {message[:64]}")
            print(f"Received EphID hash parts: {message[64:]}")
            timestamp = time.time()
            self.received_shares.append((received_ephID, received_ephID_hash, timestamp))
            self.clear_old_shares()
            if self.can_reconstruct_ephid():
                self.reconstruct_ephemeral_id()
   
    # This function removes any shares older than 9 seconds to ensure that only recent shares are considered.
    def clear_old_shares(self): ### Task 4
        current_time = time.time()
        self.received_shares = [
            (share, hash_part, timestamp)
            for share, hash_part, timestamp in self.received_shares
            if current_time - timestamp <= 9
        ]

    # This function checks if there are at least 3 shares with the same hash part
    # and if the time span between the first and last of these shares is at least 9 seconds,
    # making it possible to reconstruct the EphID.
    def can_reconstruct_ephid(self): ### Task 4
        hash_counts = {}
        for share, hash_part, timestamp in self.received_shares:
            if hash_part not in hash_counts:
                hash_counts[hash_part] = []
            hash_counts[hash_part].append((share, timestamp))

        for hash_part, shares in hash_counts.items():
            if len(shares) >= 3:
                timestamps = [timestamp for _, timestamp in shares]
                if max(timestamps) - min(timestamps) >= 9:
                    return True
        return False
    
    def reconstruct_ephemeral_id(self): ### Task 4
        # Show nodes attempting reconstruction of EphID
        print("Attempting to reconstruct EphID from received shares...")
        
        # Collect at least 3 shares with matching same EphID hash
        hash_part_counts = {}
        for share, hash_part, timestamp in self.received_shares:
            if hash_part not in hash_part_counts:
                hash_part_counts[hash_part] = []
            hash_part_counts[hash_part].append(share)
        
        for hash_part, shares in hash_part_counts.items():
            if len(shares) >= 3:
                # Reconstruct EphID from shares
                self.encounter_ephid = Shamir.reconstruct_secret(shares[:3])
                ephid_hash = hashlib.sha256(self.encounter_ephid).digest()
                # Show nodes verifying the re-constructed EphID
                print(f"Verifying reconstructed EphID: {self.encounter_ephid.hex()}")
                # Verify the reconstructed EphID hash
                if ephid_hash[:6] == hash_part:
                    print(f"Reconstructed EphID successfully verified with hash: {ephid_hash.hex()}")
                    self.perform_ecdh()
                else:
                    print("EphID verification failed. Hash does not match.")
                return
        print("Insufficient valid shares received for EphID reconstruction.")

    def perform_ecdh(self): ### Task 5
        # alice generates random number XAt
        # ephemeral id is g^XAt whic is between 0 and 1, g is a generator, and g is an elliptic curve group of order p)
        #alice gets EphIDBt which = g^YBt (YBt is a random number generated by bob at time t) alice computes the secret encounter identifier EngIDAbt = (g^Xat)^YBt
        # alice computes the secret identifier ENCIDABt = (g^XAt)^YBt
        # so g^XAt is alice's ephemeral id, and that is to the power of bob's random number, YBt).
        # need to get YBt from Bob's ephemeral ID which I am feeding into this function

        # Generate a shared key (an Encounter ID)
        self.encounter_id = self.private_key.exchange(self.encounter_ephid)
        # Show nodes have generated an Encounter ID
        print(f"Generated EncID: {self.encounter_id.hex()}")
        # Send this to a bloom filter on the server

    def bloom_filter (self): ## Task 6
        # parameters include number of entries to be stored in the filter (n), the size of the filter in bits (m), the number of hashes (k) and the false positive rate (p)
        # n is assumed to be 1000 for DBT as a worst-case representing the maximum number of close contacts per day
        # CBG can hold a maximum of 21 DBFs, the worst case CBF is 21000
        # m = 100 kB
        # k = 3
        # a bloo filter is a space efficient probabilistic data structure that is used to test whether an element is a member of a set
        # eg usernames are a set - checking the availability of a username is a membership problem
        # there might be some false positive results - eg it might tell you that given username is already taken but actually it's not
        # bloom filter is a fixed size
        # false positive rate increases as elements are addded until all queries  yield a positie result
        # bloom filters never generate a false negative result
        # can't delete elements from filter
        # need k number of hash functions to calculate the hashes for a given input

        n = 1000  # no of items to add
        p = 0.05  # false positive probability

        bloomf = BloomFilter(n, p)
        print("Size of bit array:{}".format(bloomf.size))
        print("False positive Probability:{}".format(bloomf.fp_prob))
        print("Number of hash functions:{}".format(bloomf.hash_count))

        # words to be added
        word_present = ['abound', 'abounds', 'abundance', 'abundant', 'accessible',
                        'bloom', 'blossom', 'bolster', 'bonny', 'bonus', 'bonuses',
                        'coherent', 'cohesive', 'colorful', 'comely', 'comfort',
                        'gems', 'generosity', 'generous', 'generously', 'genial']

        # word not added
        word_absent = ['bluff', 'cheater', 'hate', 'war', 'humanity',
                       'racism', 'hurt', 'nuke', 'gloomy', 'facebook',
                       'geeksforgeeks', 'twitter']

        for item in word_present:
            bloomf.add(item)

        shuffle(word_present)
        shuffle(word_absent)

        test_words = word_present[:10] + word_absent
        shuffle(test_words)
        for word in test_words:
            if bloomf.check(word):
                if word in word_absent:
                    print("'{}' is a false positive!".format(word))
                else:
                    print("'{}' is probably present!".format(word))
            else:
                print("'{}' is definitely not present!".format(word))



    def run(self):
        threading.Thread(target=self.secret_share_ephemeral_id).start()
        threading.Thread(target=self.broadcast_secret_shares).start()
        threading.Thread(target=self.receive_secret_shares).start()
        while True:
            time.sleep(1)


if __name__ == "__main__":
    client = DimyNode("127.0.0.1", 55000)
    client.run()
