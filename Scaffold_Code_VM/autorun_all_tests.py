import sys
import os
import requests
from flask import Flask, jsonify, request
import threading
#from flask_cors import CORS
import json
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from time import time, sleep

# ip5 = ['192.168.0.3','192.168.0.4','192.168.0.2','192.168.0.6','192.168.0.5']
# ip10 = ['192.168.0.3','192.168.0.4','192.168.0.2','192.168.0.6','192.168.0.5','192.168.0.3','192.168.0.4','192.168.0.2','192.168.0.6','192.168.0.5']

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
            r = requests.post("http://83.212.108.148:{}/make_new_transaction".format(5000+node_id), data = info_json)

if __name__ == '__main__':
    folderNodes = sys.argv[1]
    block_capacity = int(sys.argv[2])
    if folderNodes[-6] == '0':
        numOfNodes = 10
        # ip_array = ip10
    else:
        numOfNodes = 5
        # ip_array = ip5

    my_threads = []
    startTimer = time()

    for i in range(numOfNodes):
        new_thread = threading.Thread(target = transaction_i, args=(folderNodes+'/transactions'+str(i)+'.txt',))
        new_thread.start()
        my_threads.append(new_thread)

    for thr in my_threads:
        thr.join()

    endTimer = time()

    sleep(5)
    my_sum = 0
    local_sum = 0
    print("NUMOFNODES: "+str(numOfNodes))
    total_mining_time = 0
    total_mines = 0
    for i in range(numOfNodes):
        r = requests.get("http://83.212.108.148:{}/balance/get".format(5000+i))
        # print(r.json())
        for idx, nbc in r.json().items():
            local_sum += nbc
        local_sum -= r.json()['1000']
        print(r.json())
        print("TOTAL IN "+str(i)+": "+str(local_sum))
        local_sum = 0
        my_sum += r.json()['1000']

        r = requests.get("http://83.212.108.148:{}/mine_metrics/get".format(5000+i))
        total_mining_time += r.json()['total_mining_time']*r.json()['total_mines']
        total_mines += r.json()['total_mines']


    print("TOTAL: "+str(my_sum))
    r = requests.get("http://83.212.108.148:5000/get_chain_len")
    Totaltime = endTimer-startTimer
    ChainLength = float(r.json()['length'])
    print("ChainLength = "+str(int(ChainLength)))
    print("Throughput = {} Tr/sec".format(ChainLength*block_capacity/Totaltime))
    print("AverageMiningTime = "+str(total_mining_time/total_mines)+" sec")
