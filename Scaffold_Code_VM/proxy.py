import sys
import os
import requests
from flask import Flask, jsonify, request, render_template, send_from_directory
import webbrowser, threading
from datetime import datetime
#from flask_cors import CORS
from requests import get, post
import binascii

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

global target_ip_port

### JUST A BASIC EXAMPLE OF A REST API WITH FLASK

app = Flask(__name__)

#.......................................................................................

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>',methods=['GET'])
def proxy_get(path):
    return get(target_ip_port+path).content

@app.route('/<path:path>',methods=['POST'])
def proxy_post(path):
    return post(target_ip_port+path,data = request.data).content

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-i', '--ip', default='127.0.0.1', type=str, help='ip to listen on')
    parser.add_argument('-t_ip', '--target_ip', default='127.0.0.1', type=str, help='')
    parser.add_argument('-t_port', '--target_port', default='5000', type=str, help='')

    args = parser.parse_args()
    port = args.port
    ip = args.ip
    target_ip = args.target_ip
    target_port = args.target_port
    
    target_ip_port = "http://"+target_ip+":"+target_port+"/"

    app.run(host=ip, port=port)
