import sys
import os
import requests
from flask import Flask, jsonify, request
import threading
#from flask_cors import CORS
import json

def transaction_i(txt_name):
    with open(txt_name, 'r') as my_file:
        node_id = int(txt_name[-5])
        for line in my_file:
            line = line.strip('\n')
            line = line.split(" ")
            recipient_id = line[0][2]
            # print(recipient)
            # print(line[1])
            info_json = json.dumps({'recipient_id': int(recipient_id), 'amount': int(line[1])})
            r = requests.post("http://127.0.0.1:{}/make_new_transaction".format(5000+node_id), data = info_json)

if __name__ == '__main__':
    folderNodes = sys.argv[1]
    if folderNodes[-6] == '0':
        numOfNodes = 10
    else:
        numOfNodes = 5

    my_threads = []

    for i in range(numOfNodes):
        new_thread = threading.Thread(target = transaction_i, args=(folderNodes+'/transactions'+str(i)+'.txt',))
        new_thread.start()
        my_threads.append(new_thread)

    for thr in my_threads:
        thr.join()

    my_sum = 0
    local_sum = 0
    print("NUMOFNODES:"+str(numOfNodes))
    for i in range(numOfNodes):
        r = requests.get("http://127.0.0.1:{}/balance/get".format(5000+i))
        # print(r.json())
        for idx, nbc in r.json().items():
            local_sum += nbc
        local_sum -= r.json()['1000']
        print("TOTAL IN "+str(i)+":"+str(local_sum))
        local_sum = 0
        my_sum += r.json()['1000']

    print("TOTAL"+str(my_sum))
