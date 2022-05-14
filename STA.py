#!/usr/bin/python3

import threading
import string
import random
from datetime import date
import datetime
import argparse
import os
import socket
import time

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import hmac
import hashlib
from cryptography.hazmat.primitives import padding as blockPadding

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=str)  # id of device
    parser.add_argument('-a', type=str)  # AP name
    parser.add_argument('-m', type=str)  # Mode Hours or days
    parser.add_argument('-v', type=int)  # Token Validity

    args = parser.parse_args()

    id = args.n

    f = open("AP.txt", 'r')
    AP_details = f.read().split('\n')
    f.close()
    AP_select = '';
    for i in AP_details:
        if args.n in i:
            AP_select = i
            break

    port = int(AP_select.split(':')[1])
    # Create a socket object
    clientSocket = socket.socket()
    # connect to the AP
    clientSocket.connect(("127.0.0.1", port))

    # Connected to AP. Now, verify
    sk = ''
    try:
        f = open(f"{args.a}_token.txt", 'r')
        sk_token = f.read()
        sk = sk_token[0:16]
        token = sk_token[16:]
        print(f"{args.n} Authenticating with the token...")
        message = b'701' + id + token

        clientSocket.send(message)
        ct = clientSocket.recv(1024)

        aesccm = AESCCM(sk)
        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
        iv = ckdf.derive(sk)
        message = aesccm.decrypt(iv, ct, None)

        if message[0:3] == b'802':
            print(f"{args.n} Token Authentication Successful...")
        elif message[0:3] == b'803':
            raise Exception(f"{args.n} Token Authentication failed...")

    except:
        print(f"{args.n} Authenticate using password...")
        while True:
            key = input("Enter your password...")
            # Using PRF to generate IV
            aesccm = AESCCM(key)
            ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
            iv = ckdf.derive(key)
            nonce = os.urandom(6)
            message = id + str(nonce) + args.m + args.v
            message.encode()
            ct = aesccm.encrypt(iv, id.encode() + message, None)

            message = b'700' + id + ct

            clientSocket.send(message)
            ct = clientSocket.recv(1024)
            message = aesccm.decrypt(iv, ct, None)

            if message[0:3] == b'800' and message[3:9].decode() == nonce:
                print(f"{args.n} Authentication Successful by AS...")
                sk = message[3:19]
                id_t = message[19:27]
                nonce_t = message[27:33]
                token = message[33:]
                if nonce_t != nonce:
                    print(f"{args.n} Authentication failed, Try again....")
                    continue

                with open(f'{args.n}_token.txt', 'wb') as ft:
                    ft.write(token)

                break
            elif message[0:3] == b'801' and message[3:9].decode() == nonce:
                print(f"{args.n} Authentication failed, Try again....")

    # client is connected to AP

    # Using PRF to generate IV
    aesccm = AESCCM(sk)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
    iv = ckdf.derive(sk)
    # nonce = os.urandom(6)
    # message = id + str(nonce) + args.m + args.v
    # message.encode()

    while True:
        file = input("Enter \'exit\' to quit...\nEnter file name : ", end='')
        if file != 'exit':
            clientSocket.close()
            print("Successful connection Termination...")
            break

        try:
            message = '710' + file.encode()
            ct = aesccm.encrypt(iv, id.encode() + message, None)
            clientSocket.send(ct)
            ct = ''
            while True:
                message = clientSocket.recv(1500)
                ct += message
                if message[0] == b'0':
                    break
            message = aesccm.decrypt(iv, ct, None)
            print(message)
            with open(f'{args.n}_received.txt', 'wb') as file:
                file.write(message)

        except:
            print("Error Occured try again...")



