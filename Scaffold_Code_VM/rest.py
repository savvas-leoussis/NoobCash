import sys
import os
import requests
import subprocess
from flask import Flask, jsonify, request, render_template, send_from_directory
import webbrowser, threading
from datetime import datetime
#from flask_cors import CORS

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

from block import Block
from node import Node
#import blockchain
#import wallet
from transaction import Transaction, Transaction_Input, Transaction_Output
#import wallet
import copy


### JUST A BASIC EXAMPLE OF A REST API WITH FLASK



app = Flask(__name__)
#CORS(app)
#blockchain = Blockchain()
global node

#.......................................................................................
@app.route('/login', methods=['POST'])
def initiate_node_id():
    next_id = len(node.ring)

    # If we have all the nodes then no one else can join
    if (node.total_nodes == next_id):
        # Return Forbidden message
        return jsonify({'error': 'Forbidden'}), 403
    else:
        # Else add the new node
        next_public_key = request.form['public_key']
        next_ip = request.form['ip']
        next_port = request.form['port']
        # print(type(next_public_key))
        # print(RSA.importKey(next_public_key))
        #print(type(RSA.importKey(next_public_key)))

        # print(next_public_key)
        # node.extend_ring(next_id, port+next_id, RSA.importKey(next_public_key), 100)
        # Special Treatment for:
        # Configuration transaction
        # Sender: Bootstrap, recipient, the new node, amount 100 NBCs
        configuration_transaction = Transaction(node.wallet.get_public_key(), next_public_key, 100)
        configuration_transaction.signature = configuration_transaction.sign_transaction(binascii.hexlify(node.wallet.private_key.exportKey(format='DER')).decode('ascii'))
        configuration_transaction.transaction_id = configuration_transaction.hash()

        # if node.verify_signature(configuration_transaction):
        #     print("YOU GOT VERIFIED")
        # else:
        #     print("WE TOOK THE DICT")

        # Get the transaction_id of the first (and only) utxo of bootstrap
        # new_transaction_input = Transaction_Input(node.blockchain.chain[0].transactions[0].transaction_id)
        new_transaction_input = Transaction_Input(node.ring[node.id]['utxos'][0].originTransactionId)
        configuration_transaction.transaction_inputs.append(new_transaction_input)

        transaction_output_bootstrap = Transaction_Output(configuration_transaction.transaction_id, node.wallet.get_public_key(), node.ring[node.id]['utxos'][0].amount - 100)
        transaction_output_next = Transaction_Output(configuration_transaction.transaction_id, next_public_key, 100)

        configuration_transaction.transaction_outputs.append(transaction_output_bootstrap)
        configuration_transaction.transaction_outputs.append(transaction_output_next)

        node.ring[node.id]['utxos'] = [transaction_output_bootstrap]
        node.ring[node.id]['pre_utxos'] = copy.deepcopy(node.ring[node.id]['utxos'])

        node.extend_ring(next_id, next_ip, next_port, next_public_key, [transaction_output_next])
        node.blockchain.unconfirmed_transactions.append(configuration_transaction)

        # print("NODE {} has balance {}".format(node.id, node.wallet_balance(node.id)))

        return jsonify({'id': next_id}), 200

@app.route('/start_initialization', methods=['POST'])
def broadcast_ring_and_blockchain():
    # Make everything a dictionary
    ring = {}

    for peer_id, peer in node.ring.items():
        # print(type(peer_id))
        print("i am in")
        process = subprocess.Popen(['python3', 'proxy.py', '-i', '83.212.108.148', '-p', str(peer['port']), '-t_ip', peer['ip'], '-t_port', str(peer['port'])],shell=False,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ring[int(peer_id)] = {'ip': peer['ip'],
                             'port': peer['port'],
                             'public_key': peer['public_key'],
                             'utxos': [utxo.__dict__ for utxo in peer['utxos']],
                             'pre_utxos': copy.deepcopy([utxo.__dict__ for utxo in peer['utxos']])}

    # Convert dictionary to string
    #ring_json = json.dumps(ring)
    # print("Bazinga1")
    # print(ring_json)
    # print(ring_json[0])
    # print("Bazinga2")

    blc_idx = node.mine_block()

    if (blc_idx < 0):
        print("Error while configuring transactions")

    info = {'ring': ring, 'chain': [blc.to_dict() for blc in node.blockchain.chain]}

    #chain_json = json.dumps({'chain': [blc.to_dict() for blc in node.blockchain.chain]})

    info_json = json.dumps(info)

    for peer_id, peer in node.ring.items():
        if peer_id != 0:
            r = requests.post('http://{}:{}/initialize'.format(peer['ip'],peer['port']), json=info_json)

            if (r.status_code != 200):
                print("EXIT EVERYTHING. It has developed artificial intelligence!")
                # for peer_id, peer in node.ring.items():
                #     if peer_id == 0:
                #         requests.post('http://192.168.0.3:{}/exit'.format(peer['port']), json=ring_json)

    return jsonify({'message': 'OK'}), 200

# def format_transaction(transaction_dict):
#     new_transaction = Transaction(transaction_dict['sender_address'],
#                                   transaction_dict['recipient_address'],
#                                   transaction_dict['amount'])
#
#     new_transaction.timestamp = transaction_dict['timestamp']
#     new_transaction.transaction_id = transaction_dict['transaction_id']
#     new_transaction.transaction_inputs = [Transaction_Input(ti['previousOutputId']) for ti in transaction_dict['transaction_inputs']]
#     new_transaction.transaction_outputs = [Transaction_Output(to['originTransactionId'], to['recipient_address'], to['amount']) for to in transaction_dict['transaction_outputs']]
#     new_transaction.signature = transaction_dict['signature']
#
#     return new_transaction
#
# def format_block(block_dict):
#     new_block = Block(block_dict['index'], [format_transaction(new_tr) for new_tr in block_dict['transactions']], block_dict['previous_hash'])
#
#     new_block.timestamp = block_dict['timestamp']
#     new_block.nonce = block_dict['nonce']
#     new_block.current_hash = block_dict['current_hash']
#
#     return new_block
#
#
# def format_chain(new_chain_list):
#     new_chain = [format_block(blc) for blc in new_chain_list]
#     return new_chain

# @app.route('/exit', methods=['POST'])
# def close_port():
#     sys.exit()

############ API ############

@app.route('/initialize', methods=['POST'])
def init_ring_and_chain():
    info_dict = json.loads(request.json)

    ring_dict = info_dict['ring']
    new_chain_list = info_dict['chain']

    ring_formatted = {}

    if node.node_lock.acquire():
        for peer_id, peer in ring_dict.items():
            utxos_list = [Transaction_Output(utxo['originTransactionId'], utxo['recipient_address'], utxo['amount']) for utxo in peer['utxos']] # NEW
            pre_utxos_list = [Transaction_Output(utxo['originTransactionId'], utxo['recipient_address'], utxo['amount']) for utxo in peer['pre_utxos']] # NEW
            ring_formatted[int(peer_id)] = {'ip': peer['ip'],
                                            'port': peer['port'],
                                            'public_key': peer['public_key'],
                                            'utxos': utxos_list,
                                            'pre_utxos': pre_utxos_list} # NEW

        # Save the ring
        node.ring = ring_formatted

        # Get the chain in a good format
        new_chain = node.format_chain(new_chain_list)

        # Validate chain
        result = node.validate_chain(new_chain)

        if result:
            # Save chain
            node.blockchain.chain = new_chain
            node.node_lock.release()
            return jsonify({'message': 'OK'}), 200
        else:
            node.node_lock.release()
            return jsonify({'message': 'Invalid configuration'}), 400

@app.route('/add_block', methods=['POST'])
def receive_block():
    info_dict = json.loads(request.get_json())

    block_dict = info_dict['block']
    utxos_unformatted = info_dict['utxos']

    new_block = node.format_block(block_dict)

    result = node.validate_block(new_block, node.blockchain.last_block.current_hash)

    # local_sum = 0
    # local_sum_pre = 0
    # for peer_id, peer in node.ring.items():
    #     local_sum += node.wallet_balance(peer_id)
    #     local_sum_pre += node.wallet_balance_pre(peer_id)
    #
    # print("I GOT A BLOCK. MY SUMS ARE:")
    # print("LOCALSUM: "+str(local_sum))
    # print("LOCALSUMPRE:"+str(local_sum_pre))

    if (node.node_lock.acquire()):
        if result:
    		# self.print_utxos(self.id)
            node.blockchain.add_block(new_block)
            node.blockchain.unconfirmed_transactions = []
            for peer_id, new_utxos in utxos_unformatted.items():
                utxos_list = [Transaction_Output(utxo['originTransactionId'], utxo['recipient_address'], int(utxo['amount'])) for utxo in new_utxos]
                node.ring[int(peer_id)]['utxos'] = utxos_list # NEW
                node.ring[int(peer_id)]['pre_utxos'] = copy.deepcopy(utxos_list) # NEW

            # local_sum = 0
            # local_sum_pre = 0
            # for peer_id, peer in node.ring.items():
            #     local_sum += node.wallet_balance(peer_id)
            #     local_sum_pre += node.wallet_balance_pre(peer_id)
            #
            # print("I ACCEPTED. MY NEW SUMS ARE:")
            # print("LOCALSUM: "+str(local_sum))
            # print("LOCALSUMPRE:"+str(local_sum_pre))

        else:
            node.resolve_conflicts()
            # local_sum = 0
            # local_sum_pre = 0
            # for peer_id, peer in node.ring.items():
            #     local_sum += node.wallet_balance(peer_id)
            #     local_sum_pre += node.wallet_balance_pre(peer_id)
            #
            # print("I REJECTED. GOT BLOCKCHAIN MY NEW SUMS ARE:")
            # print("LOCALSUM: "+str(local_sum))
            # print("LOCALSUMPRE:"+str(local_sum_pre))

        node.node_lock.release()

    return jsonify({'message': 'OK'}), 200

@app.route('/add_transaction', methods=['POST'])
def receive_transaction():
    info_dict = json.loads(request.get_json())

    sender_id = int(info_dict['sender_id'])
    recipient_id = int(info_dict['recipient_id'])
    transaction_dict = info_dict['transaction']
    new_transaction = node.format_transaction(transaction_dict)

    # print("TRANSACTION")
    # print(new_transaction.sender_address)
    # print(new_transaction.recipient_address)
    # print(new_transaction.amount)
    # print(new_transaction.timestamp)
    # print([(ti.previousOutputId) for ti in new_transaction.transaction_inputs])
    # print([(to.originTransactionId, to.recipient_address, to.amount, to.uniqueId) for to in new_transaction.transaction_outputs])
    # print(new_transaction.signature)

    if node.node_lock.acquire():
        result = node.validate_transaction(sender_id, recipient_id, new_transaction)

        if result:
            node.blockchain.unconfirmed_transactions.append(new_transaction)

            # If we have capacity mine and broadcast block
            if len(node.blockchain.unconfirmed_transactions) == node.blockchain.block_capacity:
                result = node.mine_block()
                if result > 0:
                    for peer_id, peer in node.ring.items(): # NEW
                        node.ring[peer_id]['pre_utxos'] = copy.deepcopy(node.ring[peer_id]['utxos']) # NEW
                    node.broadcast_block(node.blockchain.last_block)

            node.node_lock.release()
            return jsonify({'message': 'OK'}), 200
        else:
            node.node_lock.release()
            return jsonify({'message': 'Transaction discarded'}), 400

@app.route('/get_chain_len', methods=['GET'])
def give_chain_len():
    return jsonify({'length': node.blockchain.last_block.index}), 200

@app.route('/get_chain', methods=['GET'])
def give_chain_and_utxos():
    if node.node_lock.acquire():
        my_chain = [blc.to_dict() for blc in node.blockchain.chain]
        my_utxos = {}

        # for peer_id, peer in node.ring.items():
        #     my_utxos[peer_id] = [utxo.__dict__ for utxo in peer['utxos']]

        for peer_id, peer in node.ring.items():
            my_utxos[peer_id] = [utxo.__dict__ for utxo in peer['pre_utxos']]

        node.node_lock.release()
        return jsonify({'chain': my_chain, 'utxos': my_utxos}), 200

@app.route('/make_new_transaction', methods=['POST'])
def make_new_transaction():
    # print("WE are in")
    # data1 = request.get_json()
    # print(request.data)
    data1 = json.loads(request.data.decode('utf-8'))
    # print(type(data1))
    # print("We are after json")
    # data = request.form.to_dict()
    # print(request.form)
    # print(data1)
    # print(data1['amount'])
    # print(type(data1['amount']))
    # print(type(data1['amount']))
    result = node.create_transaction(int(data1['recipient_id']), int(data1['amount']))
    if not result:
        return jsonify({'message': 'You can not make this transaction'}), 400
    else:
        return jsonify({'message': 'Success'}), 200

@app.route('/balance/get', methods=['GET'])
def get_balance():
    # response = node.wallet_balance(node.id)
    if node.node_lock.acquire():
        response = {}
        for peer_id, peer in node.ring.items():
            if node.id == peer_id:
                response[1000] = node.wallet_balance(node.id)
            response[peer_id] = node.wallet_balance(peer_id)
        node.node_lock.release()
        return jsonify(response), 200

# @app.route('/start', methods=['GET'])
# def _priget_id():
#     return jsonify({'id': 42})

# get all transactions in the blockchain
@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    transactions = node.blockchain.last_block.to_dict()['transactions']
    for transaction in transactions:
        transaction['timestamp'] = datetime.fromtimestamp(transaction['timestamp']);
    response = transactions
    return jsonify(response), 200

@app.route('/mine_metrics/get', methods=['GET'])
def get_mine_metrics():
    return jsonify({'total_mining_time': node.total_mining_time, 'total_mines': node.total_mines}), 200

######### HTML #########

@app.route('/', methods=['GET'])
def show_index():
    #print("we are in")
    return render_template('./home.html')

@app.route('/help', methods=['GET'])
def show_help():
    return render_template('./help.html')

@app.route('/new_transaction', methods=['GET'])
def show_new_transaction_form():
    return render_template('./new_transaction.html')

@app.route('/view_transactions', methods=['GET'])
def show_transactions():
    return render_template('./view_transactions.html')

@app.route('/view_balance', methods=['GET'])
def show_balance():
    return render_template('./view_balance.html')

######### JS #########
@app.route('/script.js', methods=['GET'])
def show_script():
    return render_template('./script.js')

# run it once for every node

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-i', '--ip', default='192.168.0.3', type=str, help='ip to listen on')
    parser.add_argument('-n', '--nodes', default='5', type=str, help='number of nodes')
    parser.add_argument('-d', '--difficulty', default='1', type=str, help='mining difficulty')
    parser.add_argument('-b', '--block_capacity', default='5', type=str, help='block capacity')
    #parser.add_argument('-n', '--nodes', default=3, type=int, help='number of nodes to participate - useful only for bootstrap')
    args = parser.parse_args()
    port = args.port
    ip = args.ip
    nodes= int(args.nodes)
    difficulty = int(args.difficulty)
    block_capacity = int(args.block_capacity)

    # url = 'http://192.168.0.3:{}/home'.format(port+node.id)
    # threading.Timer(1.25, lambda: webbrowser.open_new_tab(url)).start()
    node = Node(ip, port, nodes, difficulty, block_capacity)
    if (node.id == node.total_nodes - 1):
        print("WAT")
        threading.Timer(1.25, lambda: requests.post("http://192.168.0.3:5000/start_initialization")).start()
        # requests.post("http://192.168.0.3:5000/start_initialization")
    app.run(host=ip, port=port)
