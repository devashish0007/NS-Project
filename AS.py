#!/usr/bin/python3
import argparse
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import asyncio
import websockets
import threading


def add_user():
    username = input('Enter username : ')
    key = AESCCM.generate_key(bit_length=128)
    print('Username : ', username, 'Password is : ',key)
    with open(f"pask_{username}.txt", 'wb') as fu:
        fu.write(key)
    # add username & password to block chain


def modify():

    while True:
        task = input('1. Enter add to add user\n2. Enter exit to stop...\n')
        if task.lower() == 'add':
            add_user()
        elif task.lower() == 'exit':
            print("To stop AS enter ctrl + c...\n")
            break


async def response(websocket, path):
    # psk_AP key retrieve wrt id...
    psk_AP = ''
    with open('psk_AP.txt', 'rb') as f:
        psk_AP = f.read()

    message = await websocket.recv()
    ct = message[8:]
    # 8 byte of id
    id = message[0:8]
    # key retrieve wrt id...
    print(f"Retrieving key from blockchain for {id}...")
    f1 = open('psk_c.txt', 'rb')
    psk_c = f1.read()
    # key retrieve end
    # Using PRF to generate IV

    aesccm_c = AESCCM(psk_c)
    ckdf_c = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
    iv_c = ckdf_c.derive(psk_c)

    message = aesccm_c.decrypt(iv_c, ct, None)
    id_v = message[0:8]
    nonce = message[8:14]
    mode = message[14:15]
    validity = int(message[15:].decode())
    if (id == id_v):
        # user verified
        sk = AESCCM.generate_key(bit_length=128)
        if mode.lower() == 'h':
            date = datetime.datetime.now()
            date = date + datetime.timedelta(hours=validity)
            expiryTime = date.strftime("%Y-%m-%d %H:%M:%S")

        elif mode.lower() == 'd':
            date = datetime.datetime.now()
            date = date + datetime.timedelta(days=validity)
            expiryTime = date.strftime("%Y-%m-%d %H:%M:%S")

        token = sk + id + expiryTime
        # Using PRF to generate IV
        aesccm_AP = AESCCM(psk_AP)
        ckdf_AP = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
        iv_AP = ckdf_AP.derive(psk_AP)

        token = aesccm_AP.encrypt(iv_AP, token, None)

        message = sk + id + nonce + token
        ct = aesccm_c.encrypt(iv_c, message, None)
        ct = b'800' + ct + token
        await websocket.send(ct)
    else:
        await websocket.send(b'801' + (nonce + b'Invalid Credentials'))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-p', type=int)

    args = parser.parse_args()

    try:
        with open('psk_AP.txt', 'rb') as f:
            psk_AP = f.read()
    except:
        psk_AP = AESCCM.generate_key(bit_length=256)
        with open('psk_AP.txt', 'wb') as f:
            f.write(psk_AP)
    try:
        start_server = websockets.serve(response, 'localhost', args.p)
        print("AS Running...")

        t = threading.Thread(target=modify, args=())
        t.start()

        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

    except:
        print("\nAS stopped...")
