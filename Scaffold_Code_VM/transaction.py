from time import time
# from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests
from flask import Flask, jsonify, request, render_template

import hashlib
import json
from urllib.parse import urlparse
from uuid import uuid4

from collections import OrderedDict

class Transaction_Input:
    def __init__(self, transaction_id):
        self.previousOutputId = transaction_id

    def to_dict(self):
        return {'previousOutputId': self.previousOutputId}

class Transaction_Output:
    def __init__(self, originTransactionId, recipient_address, amount):
        transaction_dict = {'originTransactionId': originTransactionId,
                            'recipient_address': recipient_address,
                            'amount': amount}

        self.uniqueId = hashlib.sha256(json.dumps(transaction_dict, sort_keys=True).encode()).hexdigest()
        self.originTransactionId = originTransactionId
        self.recipient_address = recipient_address
        self.amount = amount

    def to_dict(self):
        return {'originTransactionId': self.originTransactionId,
                'recipient_address': self.recipient_address,
                'amount': self.amount}

class Transaction:

    def __init__(self, sender_address, recipient_address, amount):
        ##set

        #self.sender_address: To public key του wallet από το οποίο προέρχονται τα χρήματα
        #self.receiver_address: To public key του wallet στο οποίο θα καταλήξουν τα χρήματα
        #self.amount: το ποσό που θα μεταφερθεί
        #self.transaction_id: το hash του transaction
        #self.transaction_inputs: λίστα από Transaction Input
        #self.transaction_outputs: λίστα από Transaction Output
        #selfSignature

        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.timestamp = time()
        self.transaction_id = []
        self.transaction_inputs = []
        self.transaction_outputs = []
        self.signature = []

    # Return the transaction in Dictionary form
    # to_dict returns every attribute of Transaction class
	# No special treatment.
	# Every other function that needs specific attributes of the class
	# should create its own dictionary.
    def to_dict(self):
        transanction_inputs_to_dict = []

        for transaction_input in self.transaction_inputs:
            transanction_inputs_to_dict.append(transaction_input.to_dict())

        transanction_outputs_to_dict = []

        for transaction_output in self.transaction_outputs:
            transanction_outputs_to_dict.append(transaction_output.to_dict())

        return {"sender_address": self.sender_address,
                "recipient_address": self.recipient_address,
                "amount": self.amount,
                "timestamp": self.timestamp,
                "transaction_id": self.transaction_id,
                "transaction_inputs": transanction_inputs_to_dict,
                "transaction_outputs": transanction_outputs_to_dict,
                "signature": self.signature}

    def sign_transaction(self, sender_private_key):
        # Sign transaction with private key

        # Import the private RSA key in binary format
        spk = RSA.importKey(binascii.unhexlify(sender_private_key))

        # Public Key Certificate Standards
        # This is the signature which we will use to sign the transaction
        signer = PKCS1_v1_5.new(spk)

        # Get all the necessary info to sign in dictionary format
        info = {"sender_address": self.sender_address,
        		"recipient_address": self.recipient_address,
        		"amount": self.amount,
        		"timestamp": self.timestamp
        		}

        # Use a Secure Hash Algorithm
        # so that the dictionary can be hashable
        # h = SHA.new(str(info).encode('utf8'))

        info_str = json.dumps(info, sort_keys=True).encode()

        # Use a SHAlgorithm so that transaction can be hashable
        h = SHA.new(info_str)

        # Sign the transaction and return it decoded according to ascii
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def hash(self):
        """
		Create a SHA-256 hash of a transaction
		"""
		# Use specific attributes to calculate hash.
		# We  do not need current_hash attribute.
		# Thus we create the following sub-dictionary.

        info = {"sender_address": self.sender_address,
                "recipient_address": self.recipient_address,
                "amount": self.amount,
                "timestamp": self.timestamp,
                # "transaction_inputs": transanction_inputs_to_dict,
                # "transaction_outputs": transanction_outputs_to_dict,
                "signature": self.signature}

		# We must make sure that the Dictionary is Ordered
		# in order to avoid inconsistent hashes.
        # See the respective comment for Block class
        transaction_string = json.dumps(info, sort_keys=True).encode()

        return hashlib.sha256(transaction_string).hexdigest()

    # def print_transaction(self):
    #     print("TRANSACTION OPEN")
