from time import time
#import blockchain
from transaction import Transaction

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

class Block:
	# capacity = 5 ## SHOULD I INCREASE/DECR. IT?

	def __init__(self, index, transactions, previous_hash):
		##set

		# Initializations:
		self.index = index
		self.timestamp = time()
		self.transactions = transactions
		self.nonce = 0
		self.current_hash = []
		self.previous_hash = previous_hash

	# to_dict returns every attribute of Block class
	# No special treatment.
	# Every other function that needs specific attributes of the class
	# should create its own dictionary.
	def to_dict(self):
		transanctions_to_dict = []

		for transaction in self.transactions:
			transanctions_to_dict.append(transaction.to_dict())

		return {'index': self.index,
				'timestamp': self.timestamp,
				'transactions': transanctions_to_dict,
				'nonce': self.nonce,
				'current_hash': self.current_hash,
				'previous_hash': self.previous_hash}

	# hash() function uses to_dict()
	# The hashed string depends on every class attribute except itself.
	# Make sure that every attribute has the correct value else the hash
	# will be incosistent.
	def hash(self):
		"""
		Create a SHA-256 hash of a block
		"""
		# Use specific attributes to calculate hash.
		# We  do not need current_hash attribute.
		# Thus we create the following sub-dictionary.
		transanctions_to_dict = []

		for transaction in self.transactions:
			transanctions_to_dict.append(transaction.to_dict())

		info = {'index': self.index,
				'timestamp': self.timestamp,
				'transactions': transanctions_to_dict,
				'nonce': self.nonce,
				'previous_hash': self.previous_hash}

		# We must make sure that the Dictionary is Ordered
		# in order to avoid inconsistent hashes.
		# E.g. we use the info dictionary and the created string has:
		# index, transactions, timestamp etc. So we get hash X.
		# Another user uses info but the created string is:
		# timestamp, index,... etc. He calculates hash and he finds Y.
		# He decides that the block is invalid because he has a different
		# sorting.
		# Thus, we use sort_key parameter so that the hash is not dependent to
		# the sequence of attributes but the values of the attributes and only.
		block_string = json.dumps(info, sort_keys=True).encode()

		return hashlib.sha256(block_string).hexdigest()

	def add_transaction(self, transaction):
		#add a transaction to the block
		self.transactions.extend([transaction])
