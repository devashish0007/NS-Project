#!/usr/bin/python3
import argparse
import datetime
import hashlib
import json
import os
import socket
import sys
from multiprocessing import Process
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import asyncio
import websockets
import threading
from base64 import b64encode

seperator = b'+'
size = 100

class Blockchain():
    def __init__(self, data):

        if not data:
            self.chain = []
        else:
            self.chain = data

    def CreateBlock(self, Index, Data, Previous_hash, IV):
        
        block = {
        "Index": Index,
        "Timestamp": str(datetime.datetime.now()),
        "Data": Data,
        "IV": IV,
        "Previous_hash": Previous_hash
        }
        block["Hash"] = self.Block_hash(block)
        return block

    def Block_hash(self, block):

        block = json.dumps(block, indent = 5)
        #print(block)
        return hashlib.sha256(block.encode()).hexdigest()

    def Block_Mine(self, Data):

        previous_block = self.chain[-1]
        Previous_hash = previous_block["Hash"]
        Index = previous_block["Index"]+1
        IV = self.Proof_of_work(Index, Data)
        block = self.CreateBlock(
            Index, Data, Previous_hash, IV
            )
        self.chain.append(block)
        return block

    def add(self, block):
        self.chain.append(block)

    def Proof_of_work(self, Index, Data):

        iv = 1
        proof = False
        Data = json.dumps(Data, indent=5)

        while not proof:

            Digest = (str(iv+Index) + Data).encode()
            Hash = hashlib.sha256(Digest).hexdigest()

            if Hash[:4] == "0000":
                proof = True
            else:
                iv+=1

        return iv

    def is_valid_chain(self):

        index = self.chain[-1]["Index"]
        current_block_hash = self.chain[-1]['Hash']
        previous_block = self.chain[0]
        del previous_block['Hash']

        for i in range(1, index):
            block = self.chain[i]

            if block["Previous_hash"] != self.Block_hash(previous_block):
                print('hii')
                return False

            previous_block = block
            del previous_block['Hash']

        # current_block_hash = self.chain[-1]['Hash']
        current_block = self.chain[-1]
        # del current_block['Hash']
        if current_block_hash!= self.Block_hash(current_block):
            return False

        return True

def send(msg, conn):

    msg_length = len(msg)
    s_length = str(msg_length).encode('utf-8')
    s_length += b' '*(size-len(s_length))
    conn.send(s_length)
    conn.send(msg)

def key_generator(key):
    # Using PRF to generate IV
    aesccm = AESCCM(key)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
    iv = ckdf.derive(key)
    return aesccm, iv


def add_user():
    username = input('Enter username : ')
    key = b64encode(AESCCM.generate_key(bit_length=128))
    print('Username : ', username, '\nPassword is : ', key)
    with open(f"psk_{username}.txt", 'wb') as fu:
        fu.write(key)
    with open(f"psk_{username}.txt", 'rb') as fu:
        print(fu.read())


    # add username & password to block chain
    i = bytes(username, 'utf-8') + b'_' + key
    send(i, client)
    length_msg = client.recv(size).decode('utf-8')
    block = client.recv(int(length_msg)).decode('utf-8')
    blockchain.add(json.loads(block))



def modify():
    # try:
        while True:
            task = input()
            if task.lower() == 'add':
                add_user()
            elif task.lower() == 'exit':
                print("To stop AS enter ctrl + c to exit...")
                break
    # except:
        print("AS Stopped....")

def search(user):

    for i in blockchain.chain:
        data = i['Data'].keys()
        if user in data:
            return i['Data'][user]
    return 'abc'

def response(clientSocket, clientAddr):

# try:
    psk_AP = ''
    with open('psk_AP.txt', 'rb') as f:
        psk_AP = f.read()

    message = clientSocket.recv(1024)

    ct = message.split(seperator)
    print(ct)
    id = ct[1]
    ct = ct[2]
    # ct = ct[3]

    # Retrive client key from blockchain
    # with open(f'psk_{id.decode()}.txt', 'rb') as fc:
    #     psk_c = fc.read()

    psk_c = search(id.decode()).encode()


    print(psk_c)
    
# try:
    aesccm, iv = key_generator(psk_c)
    request = aesccm.decrypt(iv, ct, None)
    request = request.split(seperator)

    nonce = request[1]
    if id == request[0]:
        # Using PRF to generate IV

        mode = request[2]
        validity = int(request[3].decode())

        # user verified
        sk = AESCCM.generate_key(bit_length=128)
        if mode.lower() == b'h':
            date = datetime.datetime.now()
            date = date + datetime.timedelta(hours=validity)
            expiryTime = date.strftime("%Y-%m-%d %H:%M:%S")

        elif mode.lower() == b'd':
            date = datetime.datetime.now()
            date = date + datetime.timedelta(days=validity)
            expiryTime = date.strftime("%Y-%m-%d %H:%M:%S")

        token = sk + seperator + id + seperator + expiryTime.encode()
        # Using PRF to generate IV
        aesccm_AP = AESCCM(psk_AP)
        ckdf_AP = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
        iv_AP = ckdf_AP.derive(psk_AP)
        # print(token)
        token = aesccm_AP.encrypt(iv_AP, token, None)
        # print(token)
        # message = sk + seperator + id + seperator + nonce + seperator + token
        message = sk + seperator + id + seperator + nonce
        ct = aesccm.encrypt(iv, message, None)
        # print(ct)
        ct = b'800' + seperator + id + seperator + ct + seperator + token
        # print(ct)
        clientSocket.send(ct)
        # await websocket.send(ct)
        print(f"user: {id.decode()} is Authenticated...")
    else:
        clientSocket.send(b'801' + seperator + id + seperator + nonce + seperator + b'Invalid Credentials')
        print(f"user: {id.decode()}  Authentication failed...")
        # await websocket.send(b'801' + (nonce + b'Invalid Credentials'))
# except:
    nonce = os.urandom(6)
    clientSocket.send(b'801' + seperator + id + seperator + nonce + seperator +b'Invalid Credentials')
    print(f"user: {id.decode()}  Authentication failed...")

    # print("Successful")
    clientSocket.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=int)
    parser.add_argument('-n', type=int)
    parser.add_argument('-m', type=int)

    args = parser.parse_args()

    minnerport = args.m
    minnerip = socket.gethostbyname(socket.gethostname())
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((minnerip, minnerport))
    global blockchain
    global data
    try:
        with open(f"server_Bchain{args.n}.json", "r") as inputfile:
            try:
                data = json.load(inputfile)
            except:
                data = []
    except:
        with open(f"server_Bchain{args.n}.json", "w") as inputfile:
            inputfile.write('[]')
        with open(f"server_Bchain{args.n}.json", "r") as inputfile:
            data = json.load(inputfile)

    blockchain = Blockchain(data)
    if not data:
        length_msg = client.recv(size).decode('utf-8')
        block = client.recv(int(length_msg)).decode('utf-8')
        blockchain.add(json.loads(block))

    try:
        with open('psk_AP.txt', 'rb') as f:
            psk_AP = f.read()
    except:
        psk_AP = AESCCM.generate_key(bit_length=128)
        with open('psk_AP.txt', 'wb') as f:
            f.write(psk_AP)

    print("AS Running...")

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    serverSocket.bind(('', args.p))

    # socket listening
    serverSocket.listen(20)

    t = threading.Thread(target=modify, args=())
    t.start()
try:
    while True:
        print("Type Ctrl - C to Stop AS...\n1. Enter add to add user\n2. Enter exit to stop...")
        # print(serverSocket)
        clientSocket, clientAddr = serverSocket.accept()
        # print(clientSocket)
        print("connection established...")
        # t = establishConnection(clientSocket, clientAddr)
        response(clientSocket, clientAddr)
        # p = Process(target=response, args=(clientSocket, clientAddr))
        # p.start()
        # print("Thread Created...")

except:
    serverSocket.close()
    print("AS stopped...")
    with open(f"server_Bchain{args.n}.json", "w") as outputfile:
        json.dump(blockchain.chain, outputfile, indent=5)
