import socket
import threading
import time
from random import randrange
import fileinput
import argparse
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from multiprocessing import Process

host = '127.0.0.1'
port = 0
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ASserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clients = []

seperator = b'+'
sk = ''


def broadcast(message):
    print(clients)
    for client in clients:
        client.send(message)
    # print(message)


def key_generator(key):
    # Using PRF to generate IV
    aesccm = AESCCM(key)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
    iv = ckdf.derive(key)
    return aesccm, iv


def active(client, sk, id):

    aesccm, iv = key_generator(sk)
    while True:
        msg = client.recv(1024)
        try:
            request = aesccm.decrypt(iv, msg, None).split(seperator)
        except:
            break
        # print(request.split)
        try:
            with open(request[2].decode(), 'rb') as f:
                msg = f.read()
                msg = b'102' + seperator + id + seperator + aesccm.encrypt(iv, msg, None)

        except:
            msg = b'103' + seperator + id + seperator + aesccm.encrypt(iv, b"Error Occured\n", None)
            print(f"{id.decode()}: File {request[2].decode()} not found ")
        # print(f"for {id}: {sk}")
        print(f"Sending data to {id.decode()}")
        broadcast(msg)

    client.close()
    clients.remove(client)



def create_socket():
    while True:
        try:
            # reserving port
            global port
            port = randrange(50000, 60000)
            time.sleep(1)
            # Bind socket to port
            server.bind((host, port))
            server.listen()
            print(f"AP {args.n} Running...")
            f = open("AP.txt", 'a')
            f.write(f"{args.n}:{port}\n")
            f.close()
            break
        except:
            continue

    return port


def validate(id, token):
    if id == token[1]:
        exp_date = token[2].decode()
        exp_date = datetime.datetime.strptime(exp_date, '%Y-%m-%d %H:%M:%S')
        date = datetime.datetime.now()

        # date = concurrent_date.strptime("%Y-%m-%d %H:%M:%S")

        if date < exp_date:
            return True
        else:
            return False


def authenticate_token(client, ct, psk_AP):
    result = True

    ct = ct.split(seperator)
    token = ct[2]
    aesccm, iv = key_generator(psk_AP)

    # print(token)
    message = aesccm.decrypt(iv, token, None)

    token = message.split(seperator)
    # print("validating")
    if validate(ct[1], token):
        print(f"{ct[1].decode()} is verification by token completed.")
        result = False
        client.send(b'802' + seperator + args.n.encode())
    else:
        print(f"{args.n} is verification by token failed.")
        result = True
        client.send(b'803' + seperator + args.n.encode())
    return result, token[0]


def authenticate_credentials(client, ct, psk_AP):
    result = False
    print("Authenticating using Credentials.")
    message = ct
    # send message to AS...
    ASserver.connect((args.a, args.p))
    ASserver.send(message)

    message = ASserver.recv(2048)


    # print(message)
    if message[0:3] == b'801':
        result = True

        client.send(message)

    else:
        message1 = message.split(seperator)
        # print(message1)
        token = message1[3]
        token_c = token
        aesccm, iv = key_generator(psk_AP)
        # print(token)
        message = aesccm.decrypt(iv, token, None)

        token = message.split(seperator)
        if validate(message1[1], token):
            print(f"verification by credentials completed.")
            result = False
            sk = token[0]
            message = b'800' + seperator + message + seperator + token_c
        else:
            print(f"verification by Credentials failed.")
            result = True
            message = b'801' + seperator + message + seperator + token
        client.send(message)
    ASserver.close()
    return result, sk


def authenticate(psk_AP):
    while True:
        client, address = server.accept()
        ct = client.recv(1024)
        # print(ct)
        ct_msg = ct.split(seperator)
        # print(ct_msg)
        id = ct_msg[1]
        print(f'Authenticating {ct_msg[1].decode()}.')
        auth_result = False
        if ct_msg[0] == b'701':
            # Authenticate with token.
            auth_result, sk = authenticate_token(client, ct, psk_AP)

        if ct_msg[0] == b'700' or auth_result:
            if auth_result == True:
                ct = client.recv(1024)
                print(ct)
                ct_msg = ct.split(seperator)
                # print(ct_msg)
                # id = ct_msg[1]
            # Authenticating using credentials.
            auth_result, sk = authenticate_credentials(client, ct, psk_AP)

        if auth_result == False:

            clients.append(client)
            # print(f'The alias of this client is {alias}'.encode('utf-8'))
            # broadcast(f'{alias} has connected to the chat room'.encode('utf-8'))
            # client.send(b'803' + seperator + id)
            thread = threading.Thread(target=active, args=(client, sk, id))
            thread.start()
        else:
            print("Authentication Failed.")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=str)
    parser.add_argument('-d', type=int)
    parser.add_argument('-a', type=str)
    parser.add_argument('-p', type=int)

    args = parser.parse_args()

    psk_AP = ''
    try:
        with open('psk_AP.txt', 'rb') as f:
            psk_AP = f.read()

    except:
        print("AP Pre-Shared-Key not found\n AP stopped")
        raise Exception

        # print('AP is running and listening ...')
    try:
        port = create_socket()
        authenticate(psk_AP)

    except:
        server.close()
        time.sleep(2)

        result = ''
        for l in fileinput.input(files="AP.txt"):
            l = l.replace(f'{args.n}:{port}\n', '')
            result += l
            # print("successfull...")

        # print(result, f'\n\n{args.n}:{port}\n')
        with open('AP.txt', 'w') as f:
            f.write(result)

        print("AP Stopped...")
        # raise Exception
