import hashlib
import json 
import datetime as dt
import argparse
import socket

size = 100
host = socket.gethostbyname(socket.gethostname())
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class Blockchain():
	def __init__(self, data):

		if not data:
			self.chain = []
		else:
			self.chain = data

	def CreateBlock(self, Index, Data, Previous_hash, IV):
		
		block = {
		"Index": Index,
		"Timestamp": str(dt.datetime.now()),
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

def clients(conn, conn1):
	if not data:
		block = blockchain.CreateBlock(
			Data={"genesis block":"007"}, IV=1, Index=1, Previous_hash=0
		)
		blockchain.chain.append(block)
		send(json.dumps(block, indent=5).encode('utf-8'), conn)
		send(json.dumps(block, indent=5).encode('utf-8'), conn1)
	while True:
		DATA={}
		length_msg = conn.recv(size).decode('utf-8')
		msg = conn.recv(int(length_msg)).decode('utf-8').split("_")
		if msg[0]=='exit':
			send(b'exit', conn)
			send(b'exit', conn1)
			break;
		DATA[msg[0]]=msg[1]
		length_msg = conn1.recv(size).decode('utf-8')
		msg = conn1.recv(int(length_msg)).decode('utf-8').split("_")
		if msg[0]=='exit':
			send(b'exit', conn)
			send(b'exit', conn1)
			break;
		DATA[msg[0]]=msg[1]
		block = blockchain.Block_Mine(DATA)
		send(json.dumps(block, indent=5).encode('utf-8'), conn)
		send(json.dumps(block, indent=5).encode('utf-8'), conn1)
	conn.close()
	conn1.close()



def start(port):
    s.bind((host, port))
    s.listen()
    while True:
        print(f"Starts TCP server to listen on port {port}")
        conn, address = s.accept()
        conn1, address1 = s.accept()
        print("Waiting for data from clients..")
        clients(conn, conn1)
        # with open("Minner_Bchain.json", "w") as outputfile:
        # 	json.dump(blockchain.chain, outputfile, indent=5)



if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-p', type=int)
	args = parser.parse_args()
	port = args.p
	global blockchain
	global data
	try:
		with open("Minner_Bchain.json", "r") as inputfile:
			try:
				data = json.load(inputfile)
			except:
				data=[]
	except:
		with open("Minner_Bchain.json", "w") as inputfile:
			inputfile.write('[]')
		with open("Minner_Bchain.json", "r") as inputfile:
			data = json.load(inputfile)

	blockchain = Blockchain(data)
	# blockchain.Block_Mine({"chandru":"cs20m041"})

	try:
		start(port)
		# print(blockchain.chain)
	except:
		s.close()
		with open("Minner_Bchain.json", "w") as outputfile:
			json.dump(blockchain.chain, outputfile, indent=5)

	print(blockchain.is_valid_chain())

