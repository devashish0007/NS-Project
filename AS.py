#!/usr/bin/python3
import argparse
import datetime
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
import random
import string
import secrets

seperator = b'+'


def key_generator(key):
    # Using PRF to generate IV
    aesccm = AESCCM(key)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
    iv = ckdf.derive(key)
    return aesccm, iv


def get_random_string(length):
    result_str = ''.join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
                         for i in range(length))
    return result_str


def add_user():
    username = input('Enter username : ')
    # key = AESCCM.generate_key(bit_length=128)
    key = bytes(get_random_string(16), 'ascii')
    print('Username : ', username, '\nPassword is : ', key , len(key))
    with open(f"psk_{username}.txt", 'wb') as fu:
        fu.write(key)
    # add username & password to block chain


def modify():
    try:
        while True:
            task = input()
            if task.lower() == 'add':
                add_user()
            elif task.lower() == 'exit':
                print("To stop AS enter ctrl + c to exit...")
                break
    except:
        print("AS Stopped....")


def response(clientSocket, clientAddr):
    # try:
    psk_AP = ''
    with open('psk_AP.txt', 'rb') as f:
        psk_AP = f.read()

    message = clientSocket.recv(1024)

    ct = message.split(seperator)
    # print(ct)
    id = ct[1]
    ct = ct[2]
    # ct = ct[3]

    # Retrive client key from blockchain
    with open(f'psk_{id.decode()}.txt', 'rb') as fc:
        psk_c = fc.read()

    # print(ct)
    aesccm, iv = key_generator(psk_c)
    try:

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
            print(ct)
            clientSocket.send(ct)
            # await websocket.send(ct)
            print(f"user: {id.decode()} is Authenticated...")
        else:
            clientSocket.send(b'801' + seperator + id + seperator + nonce + seperator + b'Invalid Credentials')
            print(f"user: {id.decode()}  Authentication failed...")
            # await websocket.send(b'801' + (nonce + b'Invalid Credentials'))
    except:
        nonce = os.urandom(6)
        clientSocket.send(b'801' + seperator + id + seperator + nonce + seperator + b'Invalid Credentials')
        print(f"user: {id.decode()}  Authentication failed...")
    # print("Successful")
    clientSocket.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=int)

    args = parser.parse_args()

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
