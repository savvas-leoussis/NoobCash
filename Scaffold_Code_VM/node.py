import sys
import requests
from block import Block
from blockchain import Blockchain
from wallet import Wallet
from transaction import Transaction, Transaction_Input, Transaction_Output

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time, sleep
from urllib.parse import urlparse
from uuid import uuid4

import threading
import copy
from collections import OrderedDict

class Node:
	def __init__(self, ip, port, nodes, difficulty, block_capacity):
		self.NBC=100;
		##set

		#self.chain
		#self.current_id_count
		#self.NBCs
		#self.wallet

		#slef.ring[]   #here we store information for every node, as its id, its address (ip:port) its public key and its balance

		self.id = 0
		self.ip = ip
		self.port = port
		self.total_nodes = nodes
		self.wallet = self.generate_wallet()
		self.ring = {}
		self.blockchain = Blockchain(block_capacity)
		self.node_lock = threading.RLock()
		self.difficulty = difficulty
		self.total_mining_time = 0
		self.total_mines = 0

		try:
			r = requests.post("http://192.168.0.3:5000/login", data = {'public_key': self.wallet.get_public_key(), 'ip': self.ip, 'port': self.port})
			if (r.status_code == 200):
				self.id = r.json()['id']
				#print(type(self.id))
				print("I am Client Node with id "+str(self.id))
			else:
				print("Error " + str(r.status_code) + " " + r.json()['error'])
				sys.exit()

		except requests.exceptions.ConnectionError:
			# This is the bootstrap node
			# Bootstrap has id = 0
			self.id = 0

			#### Bootstrap proceeds to the following steps ####
			####         initialize the blockchain         ####
			# 1) Creates the very first blockchain
			self.blockchain = Blockchain(block_capacity)
			# 2) Creates the initial transaction with 100*(number of nodes) NBCs
			initial_transaction = Transaction(
				sender_address="00",
				recipient_address=self.wallet.get_public_key(),
				amount=100*self.total_nodes)

			#initial_transaction.signature = initial_transaction.sign_transaction("00")
			initial_transaction.signature = 0

			initial_transaction.transaction_id = initial_transaction.hash()

			# Bootstrap adds himself in the ring of participating nodes
			new_transaction_output = Transaction_Output(initial_transaction.transaction_id, self.wallet.get_public_key(), 100*self.total_nodes)
			initial_transaction.transaction_outputs.append(new_transaction_output)

			self.extend_ring(0, '192.168.0.3', '5000', self.wallet.get_public_key(), [new_transaction_output])
			# 3) Creates the genesis block
			genesis_block = Block(index=0, transactions=[initial_transaction], previous_hash="1")
			genesis_block.current_hash = genesis_block.hash()
			# print(genesis_block.current_hash)
			# print(len(genesis_block.current_hash))
			# 4) Adds it to the blockchain
			self.blockchain.chain.append(genesis_block)

			# print(self.blockchain.chain)

			#bootstrap_node, previous_hash, nonce, genesis = 0, 1, 0, True # FIXME
			#self.create_block(previous_hash, bootstrap_node, nonce, nNodes, genesis)
		return



	def extend_ring(self, id, ip, port, public_key, utxos):
		# self.ring.extend([{'id': id,
		# 				   'port': port,
		# 				   'public_key': public_key,
		# 				   'balance': balance}])
		# print(self.ring)
		self.ring[id] = {'ip': ip,
						 'port': port,
						 'public_key': public_key,
						 'utxos': utxos,
						 'pre_utxos': copy.deepcopy(utxos)} # NEW
		# if (id != 0):
		# 	print(self.blockchain.chain)
		# 	for block in self.blockchain.chain:
		# 		print("BLOCK________________________")
		# 		print(block.index)
		# 		print(block.timestamp)
		# 		print(block.transactions[0].sender_address)
		# 		print(block.transactions[0].recipient_address)
		# 		print(block.transactions[0].amount)
		# 		print(block.nonce)
		# 		print(block.previous_hash)
		# 		print("END_BLOCK____________________")

		# for node_i in self.ring.values():
		# 	print("DA LIST")
		# 	print("TRANSACTION__________________")
		# 	print(node_i['port'])
		# 	print(node_i['public_key'])
		# 	for utxo in node_i['utxos']:
		# 		print(utxo.originTransactionId)
		# 		print(utxo.recipient_address)
		# 		print(utxo.amount)
		# 	print("END TRANSACTION______________")

		# 	print(self.blockchain.chain)
		# 	for block in self.blockchain.chain:
		# 		print(block.index + " " + block.timestamp + " (" + block.transactions[0].sender_address + " " + block.transactions[0].recipient_address + " " + block.transactions[0].value + ") " + block.nonce + " " + block.previous_hash)
		# 	print(self.blockchain.chain)
		# print(self.ring[0]['public_key'])

	# We dont need this functionself.
	# We have the constructor in block.py
	# def create_new_block(self):
	# 	block = Block()
	# 	return block



	def generate_wallet(self):
		#create a wallet for this node, with a public key and a private key
		return Wallet()

	'''def register_node_to_ring():
		#add this node to the ring, only the bootstrap node can add a node to the ring after checking his wallet and ip:port address
		#bottstrap node informs all other nodes and gives the request node an id and 100 NBCs'''


	# def create_transaction(self, recipient_address, amount):
	def create_transaction(self, recipient_id, amount):
		#remember to broadcast it
		new_transaction = Transaction(self.wallet.get_public_key(), self.ring[recipient_id]['public_key'], amount)
		new_transaction.signature = new_transaction.sign_transaction(binascii.hexlify(self.wallet.private_key.exportKey(format='DER')).decode('ascii'))
		new_transaction.transaction_id = new_transaction.hash()

		to_be_removed = []
		to_add = []

		# local_sum = 0
		# local_sum_pre = 0
		# for peer_id, peer in self.ring.items():
		# 	local_sum += self.wallet_balance(peer_id)
		# 	local_sum_pre += self.wallet_balance_pre(peer_id)
		# print("I CREATE A TRANSACTION. MY SUMS ARE:")
		# print("LOCALSUM: "+str(local_sum))
		# print("LOCALSUMPRE:"+str(local_sum_pre))
		# self.print_utxos(self.id)

		if self.node_lock.acquire():
			current_amount = amount
			for utxo in self.ring[self.id]['utxos']:
				if (current_amount > 0):
					if (utxo.amount <= current_amount):
						to_be_removed.append(utxo)
						current_amount -= utxo.amount
					else:
						# rest = utxo.amount - current_amount
						to_add.append(utxo.amount - current_amount)
						to_be_removed.append(utxo)
						current_amount = 0
				else:
					break

			if (current_amount > 0):
				# print("OOPS I CANT DO IT")
				# local_sum = 0
				# local_sum_pre = 0
				# for peer_id, peer in self.ring.items():
				# 	local_sum += self.wallet_balance(peer_id)
				# 	local_sum_pre += self.wallet_balance_pre(peer_id)
				# print("LOCALSUM: "+str(local_sum))
				# print("LOCALSUMPRE:"+str(local_sum_pre))
				self.node_lock.release()
				return False
			else:
				# Fill transaction_inputs
				for utxo in to_be_removed:
					new_transaction_input = Transaction_Input(utxo.originTransactionId)
					new_transaction.transaction_inputs.append(new_transaction_input)
					self.ring[self.id]['utxos'].remove(utxo)

				# Fill transaction_outputs
				new_output_1 = Transaction_Output(new_transaction.transaction_id, self.ring[recipient_id]['public_key'], amount)
				new_transaction.transaction_outputs.append(new_output_1)
				self.ring[recipient_id]['utxos'].append(new_output_1)

				if (to_add == []):
					new_output_2 = Transaction_Output(new_transaction.transaction_id, self.wallet.get_public_key(), 0)
				else:
					new_output_2 = Transaction_Output(new_transaction.transaction_id, self.wallet.get_public_key(), to_add[0])
					self.ring[self.id]['utxos'].append(new_output_2)

				new_transaction.transaction_outputs.append(new_output_2)

			# print("I CAN DO IT. MY NEW SUMS ARE:")
			# self.print_transaction(new_transaction)
			# self.print_utxos(self.id)
			# self.print_utxos(recipient_id)
			# local_sum = 0
			# local_sum_pre = 0
			# for peer_id, peer in self.ring.items():
			# 	local_sum += self.wallet_balance(peer_id)
			# 	local_sum_pre += self.wallet_balance_pre(peer_id)
			# print("LOCALSUM: "+str(local_sum))
			# print("LOCALSUMPRE:"+str(local_sum_pre))

			# self.validate_transaction(self.id, recipient_id, new_transaction)

			# self.print_transaction(new_transaction)
			# print("for peer 0:")
			# self.print(self.ring[0]['utxos'])

			self.blockchain.unconfirmed_transactions.append(new_transaction)
			# If we have capacity mine and broadcast block
			if len(self.blockchain.unconfirmed_transactions) == self.blockchain.block_capacity:
				result = self.mine_block()
				if result > 0:
					for peer_id, peer in self.ring.items(): # NEW
						self.ring[peer_id]['pre_utxos'] = copy.deepcopy(self.ring[peer_id]['utxos']) # NEW
					# print("I MINE:")
					# local_sum = 0
					# local_sum_pre = 0
					# for peer_id, peer in self.ring.items():
					# 	local_sum += self.wallet_balance(peer_id)
					# 	local_sum_pre += self.wallet_balance_pre(peer_id)
					# print("LOCALSUM: "+str(local_sum))
					# print("LOCALSUMPRE:"+str(local_sum_pre))
					# if (local_sum != self.total_nodes*100):
					# 	print("localsum bad")
					# 	sleep(3600)
					# if (local_sum_pre != self.total_nodes*100):
					# 	print("localsum pre bad")
					# 	sleep(3600)
					self.broadcast_block(self.blockchain.last_block)

			# print("TRANSACTION")
			# print(new_transaction.sender_address)
			# print(new_transaction.recipient_address)
			# print(new_transaction.amount)
			# print("ID:"+new_transaction.transaction_id)
			# print(new_transaction.timestamp)
			# print([(ti.previousOutputId) for ti in new_transaction.transaction_inputs])
			# print([(to.originTransactionId, to.recipient_address, to.amount, to.uniqueId) for to in new_transaction.transaction_outputs])
			# print(new_transaction.signature)

			# Broadcast transaction
			self.broadcast_transaction(recipient_id, new_transaction)

			self.node_lock.release()
		return True

	def broadcast_transaction(self, recipient_id, transaction):
		# transaction_json = json.dumps(transaction.to_dict())
		info = {'sender_id': self.id,
				'recipient_id': recipient_id,
				'transaction': transaction.to_dict()}

		info_json = json.dumps(info)

		for peer_id, peer in self.ring.items():
			if peer_id != self.id:
				threading.Thread(target = (lambda: requests.post("http://{}:{}/add_transaction".format(peer['ip'], peer['port']), json=info_json))).start()

	def verify_signature(self, transaction):
		# Get the public key of sender from the field in transaction
		public_key = RSA.importKey(binascii.unhexlify(transaction.sender_address))

		# Create a verifier from the public key according to PKCStandards
		verifier = PKCS1_v1_5.new(public_key)

		# We verify the transaction on the attributes that were actually used
		# to create the signatuure in the first place
		info = {"sender_address": transaction.sender_address,
				"recipient_address": transaction.recipient_address,
				"amount": transaction.amount,
				"timestamp": transaction.timestamp
				}

		info_str = json.dumps(info, sort_keys=True).encode()

		# Use a SHAlgorithm so that transaction can be hashable
		h = SHA.new(info_str)

		# Return the result of the verification
		return verifier.verify(h, binascii.unhexlify(transaction.signature))

	def validate_transaction(self, sender_id, recipient_id, transaction):
		#use of signature and NBCs balance
		# print("Check signature")
		# print("TRANSACTION")
		# print(transaction.sender_address)
		# print(transaction.recipient_address)
		# print(transaction.amount)
		# print("ID:"+transaction.transaction_id)
		# print(transaction.timestamp)
		# print([(ti.previousOutputId) for ti in transaction.transaction_inputs])
		# print([(to.originTransactionId, to.recipient_address, to.amount, to.uniqueId) for to in transaction.transaction_outputs])
		# print(transaction.signature)
		if not self.verify_signature(transaction):
			return False

		# print("signature success")
		sender_utxos = self.ring[sender_id]['utxos']

		to_be_removed = []
		found_ti = False

		# for peer_id, peer in self.ring.items():
		# 	print("Peer {} has".format(peer_id))
		# 	for utxo in peer['utxos']:
		# 		print(utxo.originTransactionId)

		for ti in transaction.transaction_inputs:
			# print(ti.previousOutputId)
			for idx, utxo in enumerate(sender_utxos):
				# print(utxo.originTransactionId)
				if ti.previousOutputId == utxo.originTransactionId:
					to_be_removed.append(idx)
					found_ti = True
					break
			if not found_ti:
				# print("utxos failed though")
				return False
			found_ti = False

		# Indicies in descending order
		to_be_removed.sort(reverse=True)

		# Remove used utxos
		for idx in to_be_removed:
			del self.ring[sender_id]['utxos'][idx]

		# Find the output for the sender and for the recipient
		if transaction.transaction_outputs[0].recipient_address == self.ring[recipient_id]['public_key']:
			output_recipient = transaction.transaction_outputs[0]
			output_sender = transaction.transaction_outputs[1]
		else:
			output_recipient = transaction.transaction_outputs[1]
			output_sender = transaction.transaction_outputs[0]

		# The recipient always has an output
		self.ring[recipient_id]['utxos'].append(output_recipient)

		# The sender may have a 0 zmount output so there is no need to
		# add it in utxos
		if output_sender.amount != 0:
			self.ring[sender_id]['utxos'].append(output_sender)

		return True

	# def add_transaction_to_block():
	# 	#if enough transactions  mine
	#
	#
	#
	#
	#

	def proof_of_work(self, block):
		# Function that tries different values of nonce to get a hash
		# that satisfies our difficulty criteria.
		block.nonce = 0

		computed_hash = block.hash()
		while not computed_hash.startswith('0' * self.difficulty):
			block.nonce += 1
			computed_hash = block.hash()

		return computed_hash

	def mine_block(self):
		# This function serves as an interface to add the pending
		# transactions to the blockchain by adding them to the block
		# and figuring out Proof Of Work.

		# if not self.unconfirmed_transactions:
		#     return False
		startTimer = time()

		last_block = self.blockchain.last_block

		new_block = Block(index=last_block.index + 1,
		              	  transactions=self.blockchain.unconfirmed_transactions,
		              	  previous_hash=last_block.current_hash)

		proof = self.proof_of_work(new_block)
		new_block.current_hash = proof
		answer = self.validate_block(new_block, last_block.current_hash)

		if answer:
			self.blockchain.add_block(new_block)
			self.blockchain.unconfirmed_transactions = []
			endTimer = time()
			self.total_mining_time += endTimer-startTimer
			self.total_mines += 1
			return new_block.index
		else:
			print("Failed to add block")
			return -1

	def validate_block(self, block, previous_hash):
		# Verify that current_hash is correct
		if not self.is_valid_proof(block, block.current_hash):
			print("Block with index {} does not have a correct hash.".format(block.index))
			return False

		# Verify that the previous_hash matches the hash of the previous block
		if (block.previous_hash != previous_hash):
			print("Block with index {} does not have a correct previous hash.".format(block.index))
			return False

		return True

	def is_valid_proof(self, block, block_hash):
		# Check if block_hash is valid hash of block and satisfies
		# the difficulty criteria.

		return (block_hash.startswith('0' * self.difficulty) and
				block_hash == block.hash())


	def broadcast_block(self, block):
		# block_json = json.dumps(block.to_dict())
		my_utxos = {}

		for peer_id, peer in self.ring.items():
		    my_utxos[peer_id] = [utxo.__dict__ for utxo in peer['pre_utxos']] # NEW

		info = {'block': block.to_dict(),
				'utxos': my_utxos}

		info_json = json.dumps(info)

		for peer_id, peer in self.ring.items():
			if peer_id != self.id:
				threading.Thread(target = (lambda: requests.post("http://{}:{}/add_block".format(peer['ip'], peer['port']), json=info_json))).start()

	#
    # def valid_proof(..., difficulty=self.difficulty):
	# 	pass
	#
	#
	#
	#
	#
	#
	# #concencus functions
	#
	def validate_chain(self, chain):
		#check for the longer chain accroose all nodes
		previous_hash = chain[0].current_hash

		for blc in chain:
			if blc.index != 0:
				valid_block = self.validate_block(blc, previous_hash)
				if not valid_block:
					return False

		return True

	# Decoration functions
	def wallet_balance(self, owner_id):
		balance = 0

		for utxo in self.ring[owner_id]['utxos']:
			balance += utxo.amount

		return balance

	def wallet_balance_pre(self, owner_id):
		balance = 0

		for utxo in self.ring[owner_id]['pre_utxos']:
			balance += utxo.amount

		return balance

	# def view_transactions(self):
	# 	last_block = self.blockchain.last_block

	def resolve_conflicts(self):
		#resolve correct chain
		# My blockchain length
		my_len = self.blockchain.last_block.index
		max_len = my_len

		for peer_id, peer in self.ring.items():
			r = requests.get('http://{}:{}/get_chain_len'.format(peer['ip'], peer['port']))
			if (r.status_code == 200):
				new_len = r.json()['length']
				if new_len > max_len:
					max_len = new_len
					max_id = peer_id

		if my_len < max_len:
			r = requests.get('http://{}:{}/get_chain'.format(self.ring[max_id]['ip'], self.ring[max_id]['port']))
			if (r.status_code == 200):
				new_chain_unformatted = r.json()['chain']
				new_chain = self.format_chain(new_chain_unformatted)
				self.blockchain.chain = new_chain

				new_utxos_unformatted = r.json()['utxos']
				for peer_id, new_utxos in new_utxos_unformatted.items():
					self.ring[int(peer_id)]['utxos'] = [Transaction_Output(utxo['originTransactionId'], utxo['recipient_address'], int(utxo['amount'])) for utxo in new_utxos]
					self.ring[int(peer_id)]['pre_utxos'] = copy.deepcopy(self.ring[int(peer_id)]['utxos']) # NEW

				self.blockchain.unconfirmed_transactions = []

	def format_transaction(self, transaction_dict):
		new_transaction = Transaction(transaction_dict['sender_address'],
									  transaction_dict['recipient_address'],
									  int(transaction_dict['amount']))

		new_transaction.timestamp = transaction_dict['timestamp']
		new_transaction.transaction_id = transaction_dict['transaction_id']
		new_transaction.transaction_inputs = [Transaction_Input(ti['previousOutputId']) for ti in transaction_dict['transaction_inputs']]
		new_transaction.transaction_outputs = [Transaction_Output(to['originTransactionId'], to['recipient_address'], int(to['amount'])) for to in transaction_dict['transaction_outputs']]
		new_transaction.signature = transaction_dict['signature']

		return new_transaction

	def format_block(self, block_dict):
	    new_block = Block(block_dict['index'], [self.format_transaction(new_tr) for new_tr in block_dict['transactions']], block_dict['previous_hash'])

	    new_block.timestamp = block_dict['timestamp']
	    new_block.nonce = block_dict['nonce']
	    new_block.current_hash = block_dict['current_hash']

	    return new_block

	def format_chain(self, new_chain_list):
	    new_chain = [self.format_block(blc) for blc in new_chain_list]
	    return new_chain

	def print_transaction(self, transaction):
		print("Check signature")
		print("TRANSACTION")
		print("SA:"+transaction.sender_address)
		print("RA:"+transaction.recipient_address)
		print("AM:"+str(transaction.amount))
		print("ID:"+transaction.transaction_id)
		print("TM:"+str(transaction.timestamp))
		print("TIs:")
		print([(ti.previousOutputId) for ti in transaction.transaction_inputs])
		print("TOs:")
		print([(to.originTransactionId, to.recipient_address, to.amount, to.uniqueId) for to in transaction.transaction_outputs])
		print("SI:"+transaction.signature)

	def print_utxos(self, peer_id):
		for utxo in self.ring[peer_id]['utxos']:
			print("utxo:")
			print("OrID:"+utxo.originTransactionId)
			print("RA:"+utxo.recipient_address)
			print("AM:"+str(utxo.amount))
			print("UID:"+utxo.uniqueId)
