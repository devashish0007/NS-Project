#!/usr/bin/python3
import argparse
import datetime
import socket
import threading
import string
import random
from datetime import date
import time
from random import randrange

import asyncio
import websockets

c = threading.Condition()
devices = 0


async def verification(msg, port):
    async with websockets.connect(f"ws://localhost:{port}") as socket:
        await socket.send(msg)
        receive = await socket.recv()
        print(receive)


def establishConnection(clientSocket, clientAddr):
    global devices

    asyncio.get_event_loop().run_until_complete(verification())

    # Establish connection with client.
    print(f"{clientAddr} is connected...")
    # send a message to the client. encoding to send byte type.
    clientSocket.recv(1500)

    while True:
        try:
            # receive client credentials for authentication.
            request = clientSocket.recv(1500)
            if request[0] == b'1':
                print("Authentication Login...")
                break
            elif request[0] == b'2':
                print("Token Authentication...")
                break
            else:
                print("Incorrect Credentials...")

        except:
            print(f"Connection closed with {clientAddr}...")
            clientSocket.close()
            return

    while True:
        request = clientSocket.recv(1500)
        print(request)
        message = b'recived succesfully'
        clientSocket.send(message)

    # Close the connection with the client
    clientSocket.close()
    c.acquire()
    devices -= 1
    c.release()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=str)
    parser.add_argument('-d', type=int)
    parser.add_argument('-a', type=str)
    parser.add_argument('-p', type=int)

    args = parser.parse_args()
    global devices
    devices = args.d
    # Create a socket
    serverSocket = socket.socket()

    while True:
        try:
            # reserving port
            port = randrange(50000, 60000)
            time.sleep(1)
            # Bind socket to port
            serverSocket.bind(('', port))
            print("AP Running...")
            break
        except:
            # print("Socket Binding Successful...")
            continue

    f = open("AP.txt", 'a')
    f.write(f"{args.n}:{port}\n")
    f.close()

    # socket listening
    serverSocket.listen(10)

    try:
        # a forever loop until we interrupt it or an error occurs
        while True:
            print("Type Ctrl - C to Stop AP")
            while True:
                c.acquire()
                if devices > 0:
                    devices -= 1
                    clientSocket, clientAddr = serverSocket.accept()
                    t = threading.Thread(target=establishConnection, args=(clientSocket, clientAddr))
                    t.start()
                c.release()

    except:
        serverSocket.close()
        time.sleep(2)
        f = open("AP.txt", 'w+')
        data = f.read()
        data.replace(f"{args.n}:{port}\n", "")
        f.write(data)
        f.close()
        print("AP Stopped...")
