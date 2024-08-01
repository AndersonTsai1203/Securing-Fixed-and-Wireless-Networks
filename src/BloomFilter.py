import math
import mmh3
from bitarray import bitarray


class BloomFilter(object):

	'''
	Class for Bloom filter, using murmur3 hash function
	'''

	def __init__(self, size, hashes):
		'''
		items_count : int
			Number of items expected to be stored in bloom filter
		fp_prob : float
			False Positive probability in decimal
		'''

		# Size of bit array to use
		self.size = size

		# number of hash functions to use
		self.hash_count = hashes

		# Bit array of given size
		self.bit_array = bitarray(self.size)

		# initialize all bits as 0
		self.bit_array.setall(0)

	def add(self, item):
		'''
		Add an item in the filter
		'''
		digests = []
		for i in range(self.hash_count):

			# create digest for given item.
			# i work as seed to mmh3.hash() function
			# With different seed, digest created is different
			digest = mmh3.hash(item, i) % self.size
			digests.append(digest)

			# set the bit True in bit_array
			self.bit_array[digest] = True

	def check(self, item):
		'''
		Check for existence of an item in filter
		'''
		for i in range(self.hash_count):
			digest = mmh3.hash(item, i) % self.size
			if self.bit_array[digest] == False:

				# if any of bit is False then,its not present
				# in filter
				# else there is probability that it exist
				return False
		return True

	def bits_non_zero(self):
		print(f"Number of non-zero bits in bloom filter: {self.bit_array.count(1)}")

	def to_bytes(self):
		return self.bit_array.tobytes()



