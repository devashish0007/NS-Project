import argparse
import os
import socket
import threading
from builtins import Exception
from time import sleep

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

seperator = b'+'


def key_generator(key):
    print(type(key), len(key))
    # Using PRF to generate IV
    aesccm = AESCCM(key)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=13, otherinfo=None)
    iv = ckdf.derive(key)

    return aesccm, iv


def client_receive(client, sk, aesccm, iv):
    while True:

        ct = client.recv(1024)
        aesccm, iv =key_generator(sk)
        message = ct.split(seperator)
        print(sk)
        print('Received:', message)
        # print(sk)
        # print( args.n.encode(), message[1])
        try:

            if args.n.encode() == message[1] and b'102' == message[0]:
                # print(f"\nmessage encrypted content:\n {ct}")
                message = aesccm.decrypt(iv, message[2], None)
                print(f"\nmessage decrypted content...\n")
                print(message)
                with open(f'{args.n}_received.txt', 'wb') as f:
                    f.write(message)
            elif args.n.encode() == message[1] and b'103' == message[0]:
                print("File not found...")

            else:
                print(f"message discarded...\n")
        except:
            # print(Exception)
            print(f'Error Occured try again....')
            # client.close()
            # exit()
            break


def client_send(client, sk, aesccm, iv):
    while True:
        file = input("Enter file name: \n").encode()
        message = b'101' + seperator + args.n.encode() + seperator + file
        ct = aesccm.encrypt(iv, message, None)
        client.send(ct)
        sleep(1)




def active(client, sk, aesccm, iv):
    receive_thread = threading.Thread(target=client_receive, args=(client, sk, aesccm, iv))
    receive_thread.start()

    send_thread = threading.Thread(target=client_send, args=(client, sk, aesccm, iv))
    send_thread.start()


def authenticate_token(client):
    try:
        f = open(f"{args.n}_token.txt", 'rb')
        sk_token = f.read()
        f.close()
    except:
        authenticate_credentials(client)
        return

    # print(sk_token)
    sk_token = sk_token.split(seperator)
    sk = sk_token[0]
    token = sk_token[1]
    print(f"{args.n} Authenticating with the token...")
    message = b'701' + seperator + args.n.encode() + seperator + token
    client.send(message)
    ct = client.recv(1024)
    # print(ct)
    aesccm, iv = key_generator(sk)
    # message = aesccm.decrypt(iv, ct, None)

    message = ct.split(seperator)

    if message[0] == b'802':
        print(f"{args.n}'s Token Authentication Successful...")
        active(client, sk, aesccm, iv)

    elif message[0] == b'803':
        print(f"Token Authentication failed...")
        # print(f"{args.n} Token Authentication failed...")
        authenticate_credentials(client)


def authenticate_credentials(client):
    print(f"Authenticate using password file...")
    # print(f"{args.n} Authenticate using password file...")

    key_file = input("Enter your password file name...\n")
    with open(key_file, 'rb') as kf:
        psk_key = kf.read()
    # print("Working Good...1")
    aesccm, iv = key_generator(psk_key)

    nonce = os.urandom(6)

    message = args.n.encode() + seperator + nonce + seperator + args.m.encode() + seperator + str(args.v).encode()
    ct = aesccm.encrypt(iv, message, None)
    message = b'700' + seperator + args.n.encode() + seperator + ct
    client.send(message)
    # print(message)
    message = client.recv(1024)

    message = message.split(seperator)

    if message[0] == b'800':
        print(f"Authentication Successful...")
        # print(f"{args.n}'s Authentication Successful...")
        with open(f'{args.n}.txt', 'wb') as f:
            f.write(message[4])

        id = message[2]
        # ct = message[2]
        # print(message)
        # message = aesccm.encrypt(iv, ct, None).split(seperator)
        if id != args.n.encode():
            print('Error Occurred...')

            exit()
        sk = message[1]
        token = message[4]
        with open(f'{id.decode()}_token.txt', 'wb') as kf:
            kf.write(sk+seperator+token)

        aesccm, iv = key_generator(sk)
        active(client, sk, aesccm, iv)

    elif message[0] == b'801':
        # raise Exception(f"{args.n}  Authentication failed...")
        print(f"Authentication failed...")


def search_AP(AP):
    f = open("AP.txt", 'r')
    AP_details = f.read().split('\n')
    f.close()
    AP_select = ''
    found = False

    for i in AP_details:
        if AP in i:
            AP_select = i
            found = True
            break

    if found == False:
        print(f"AP {AP} is not Available...")
        exit()
    else:
        print(f"connecting to  {AP}...")

    port = int(AP_select.split(':')[1])

    # Create a socket object
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to the AP
    clientSocket.connect(("127.0.0.1", port))

    return clientSocket



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=str)  # id of device
    parser.add_argument('-a', type=str)  # AP name
    parser.add_argument('-m', type=str, default='h')  # Mode Hours or days
    parser.add_argument('-v', type=int, default=1)  # Token Validity

    args = parser.parse_args()
    # Search & Connect AP
    client = search_AP(args.a)

# try:
    authenticate_token(client)
# except:

    # try:
    #     authenticate_credentials(client)
    # except:
    #     print("Authentication Failed")
    #     client.close()
    #     raise Exception
    #     exit()
