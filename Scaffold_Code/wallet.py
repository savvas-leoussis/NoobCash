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



class Wallet:

	def __init__(self):
		##set

		#self.public_key
		#self.private_key
		#self_address
		#self.transactions

		# Initializations:
		# RSA length is 1024 bits, so it can be fast and secure enoughself.
		# We can set it at 2048 (multiple of 256)
		self.private_key = RSA.generate(1024, Crypto.Random.new().read)
		# Create the private key according to the private key
		self.public_key = self.private_key.publickey()
		# print(self.private_key)
		# print(type(self.private_key))

	def balance():
		return 100

	def get_public_key(self, format='string'):
		if (format == 'string'):
			return binascii.hexlify(self.public_key.exportKey(format='DER')).decode('ascii')
			# return self.public_key.exportKey(format='OpenSSH')
		elif (format == 'none'):
			return self.public_key
		else:
			print("Wrong format. Returning string.")
			return binascii.hexlify(self.wallet.public_key.exportKey(format='DER')).decode('ascii')
