import sys
import os
import requests
from flask import Flask, jsonify, request
import threading
#from flask_cors import CORS
import json

with open(sys.argv[1], 'r') as my_file:
    node_id = int(sys.argv[1][-5])
    for line in my_file:
        line = line.strip('\n')
        line = line.split(" ")
        recipient_id = line[0][2]
        # print(recipient)
        # print(line[1])
        info_json = json.dumps({'recipient_id': int(recipient_id), 'amount': int(line[1])})
        r = requests.post("http://192.168.0.3:{}/make_new_transaction".format(5000+node_id), data = info_json)
