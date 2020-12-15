import hashlib
import json
from time import time
from urllib.parse import urlparse
import urllib.request
from uuid import uuid4
import requests

from flask import Flask, jsonify, request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# blockchain
# takes in title of book(blockchain) and the current owner of the-
# book( the host url ), the nodes that added the book(blockchain)
class Blockchain:
    def __init__(self,title, host_address):
        self.title = title
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        

        self.private_key = ec.generate_private_key(ec.SECP384R1())

        # Create the genesis block
        self.current_transactions.append({
            'sender':f'http://{host_address}',
            'recipient':f'http://{host_address}'
        })
        self.new_block(previous_hash='1', proof=100)
    # parses and stores the url of the nodes
    def register_node(self, address):
        
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
           
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')
    # verifies that the chain is legitimate and hasn't been alters
    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True
    # hashes the blockchain
    def hashed_chain(self,chain):
        hashed_chain = hashes.Hash(hashes.SHA256())

        for block in chain:
            hashed_chain.update(str(block["index"]).encode())
            hashed_chain.update(str(block["previous_hash"]).encode())
            hashed_chain.update(str(block["proof"]).encode())

        return hashed_chain.finalize().hex()

    # creates a signiture from hashed blockchain and public key
    def get_signature(self):
        hash = bytes.fromhex(self.hashed_chain(self.chain))
        signature = self.private_key.sign(
            hash,
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

    # checks which valid blockchain should be used to overwrite current blockchain
    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        
        max_length = len(self.chain)
        
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['bookchain']
                signature = bytes.fromhex(response.json()['signature'])
                public_key = serialization.load_der_public_key(bytes.fromhex(response.json()['public_key']))

                try:
                    check = bytes.fromhex(self.hashed_chain(chain))
                    public_key.verify(signature, check, ec.ECDSA(hashes.SHA256())) 
                except:
                    return False
                
              
                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
            

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True
   
        return False
 
    # adds new json formatted block to blockchain
    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),

        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    # adds new transaction to be added to the block
    def new_transaction(self, sender, recipient):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
          
        })

        return self.last_block['index'] + 1

    # returns last block in blockchain
    @property
    def last_block(self):
        return self.chain[-1]

    # hashes block
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    # rehashes block until a valid hash is produced
    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        """ rehashes specified data until desired outcome is performed """
        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    # checks if the hash has specific pattern
    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        checks if hash has set pattern

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
    
# a library that manages the books(Blockchain)
# only has functions that manage the books, all the functionality to chanage the book
# reside in the book(Blockchain)
class Booklib:
    def __init__(self):
        
        self.book_arr = [] 
        self.current_book = None
        self.nodes = set()
        self.private_key = ec.generate_private_key(ec.SECP384R1)
        self.temp_block = {}
  

  #recent change public_key -> host_url


    # makes a unique address using hosts public key and a hash
    def addressHash(self,host_url):
        temphash = hashes.Hash(hashes.SHA256())

        temphash.update(str(host_url).encode())
        return temphash.finalize().hex()







    # assuming host has all books in network
    # iterates through hosts book_arr to return index if book exists
    # checks each book's title and compares it with target title
    def findBook(self,title):
        for index in range(0,len(self.book_arr)):
            if self.book_arr[index].title == title:
                return index
        return False
                
    # jsonifies the host's book_arr
    # iterates through host's book_arr, converts into json format, and appends temp chain
    # to display chain of books in json format
    # each item is named after the book
    def show_books(self):
        books_chain = []
        for book in self.book_arr:
            books_chain.append( {
                book.title:{
                    "chain_length" : len(book.chain),
                    'bookchain': book.chain
                }
            })
        return books_chain
    
    # checks if there even books to select from
    def is_empty(self):
        return len(self.book_arr) == 0

    # assuming books are in host's book_arr
    # compares target title with titles in host's book_arr and sets book to current book if true
    def set_current_book(self,title):
        for index in range(0,len(self.book_arr)):
            if self.book_arr[index].title == title:
                self.current_book = self.book_arr[index]
               
    # checks if target title is in host's book_arr
    # iterates through host's book_arr, compares book title with target title
    # if comparison is true, sets host's current book with target book
    # returns bool
    def if_exists(self, title):
        for index in range(0,len(self.book_arr)):
            if self.book_arr[index].title == title:
                self.current_book = self.book_arr[index]
                return 1
        return 0
    
    # parses address and adds to host's node set
    def add_book_nodes(self, address):

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    # assuming all nodes were added and no additional nodes are added
    # makes sure all current nodes are updated with each new book
    # calls route of each node that updates its own library
    def resolve_books(self):
        neighboors = self.nodes
        book = {
            'title': self.current_book.title,
            'chain': self.current_book.chain,
            'hostaddress': self.current_book.chain[0]['transactions'][0]['recipient']
        }
        for node in neighboors:
            response = requests.post(f'http://{node}/book/synch', json={'book': book})

    # checks if address is legitamate
    # recreates the address using the public key
    # if the comparison matches return True
    def verify_address(self, public_key, book_index, address_signature):
        signature = bytes.fromhex(address_signature)
        public_key = serialization.load_der_public_key(bytes.fromhex(public_key))
        
        try:
            check = bytes.fromhex(self.addressHash(self.book_arr[book_index].chain[-1]['transactions'][0]['recipient']))
            public_key.verify(signature, check, ec.ECDSA(hashes.SHA256())) 
        except:
            return False

        print(self.book_arr[book_index].chain[-1]['transactions'][0]['recipient'])
        
        return True



    # broadcasts address
    # creates public and serialized public key
    # calls routes of other nodes and passes the address and the serialized public key
    # passes keys to all existing nodes to verify that the serialized public key can recreate address
    # if that is the case, then the user is verified
    # uses consensus method in terms of majority means the user is verified
    def broadcast_address(self, book_index, host_address):
        neighboors = self.nodes
        public_key = self.private_key.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        signature = self.private_key.sign(
            bytes.fromhex(self.addressHash(f'http://{request.host}')),
            ec.ECDSA(hashes.SHA256())
        )

        print(f'this is http://{request.host},this is book_index{book_index} and this is the signiture created from it',signature.hex())

        

        keys = {
            'public_key':serialized_public_key.hex(),
            'address_signature': signature.hex(),
            'book_index':book_index
        }
        verified = 0  
        # if the response code is 201 then user has been verified by a node and verified should be incremented 
        for node in neighboors:
            if(node != host_address):
                response = requests.post(f'http://{node}/verifyID', json={'ID':keys})
                if(response.status_code == 201):
                    verified += 1
        if(verified >= (len(neighboors)/2)): # verification rule
            return True
        return False












    # calls the target user to do something
    # passes target url, host url, and target title
    # returns a bool depending on response status code
    def ping_node(self,node_url, title, hosturl):
        response = requests.post(f'{node_url}/ping', json={'title':title,'hosturl':hosturl})
        if(response.status_code == 201):
            return True
        return False
       
    # finds owner of the book
    # finds if the book even exists in host's book_arr
    # calls class function, findBook(), to return index of book
    # uses index for host's book_arr and specify target object's route
    # target object is the recipient in the last block, the most recent block added
    # returns the owners url if book exists in host's book_arr and the the book is found
    # returns string book doesn't exist otherwise
    def find_owner(self,title):
        if(self.if_exists(title)):
            owner = self.book_arr[self.findBook(title)].chain[-1]['transactions'][-1]['recipient']
            return owner
        return 'book doesn\'t exist' 

    # updates all node's current book chain
    # update includes verified book's chain and ownership
    # calls all nodes to use built-in book(Blockchain) functionality to resolve conflict
    def mass_consensus(self):
        neighboors = self.nodes
        for node in neighboors:
            response = requests.post(f'http://{node}/nodes/resolve')
        return



     # hashes block values
    def hashValues(self, index, proof, prev_hash):
        hashed_block = hashes.Hash(hashes.SHA256())

        hashed_block.update(str(index).encode())
        hashed_block.update(str(proof).encode())
        hashed_block.update(str(prev_hash).encode())

        return hashed_block.finalize().hex()
    # hashes the chain and merges hash with the hash received
    def updateChainHash(self,block_hash):
        hashed_chain = hashes.Hash(hashes.SHA256())
        for block in self.current_book.chain:
            hashed_chain.update(str(self.hashValues(block["index"],block["proof"],block["previous_hash"])).encode())
        hashed_chain.update(str(block_hash).encode())

        return hashed_chain.finalize().hex()
    # consensus function
    # sends selected data to have verified
    def distributeHash(self,blockchain_hash,owner_url):
        verifies = 0

        for node in self.nodes:
            if(node != owner_url):
                response = requests.post(f'http://{node}/verify/hash', json={'blockchain_hash': blockchain_hash, 'owner_url': owner_url})
                if(response.status_code == 201):
                    verifies += 1
        if (verifies >= len(self.nodes)/2):
            return True
        return False


    

    # new code ^^^^
    




   

           




        
       
        


    


       

        



# Instantiate the Node
app = Flask(__name__)


booklib = Booklib()

# copies all the information of the book and updates host's book_arr
@app.route('/book/synch', methods=['POST'])
def resolve_book():
    values = request.get_json()
    new_book = Blockchain(values['book']['title'],values['book']['hostaddress'])
    new_book.chain = values['book']['chain']
    new_book.nodes = booklib.nodes
    booklib.book_arr.append(new_book)
    return 'synch', 201

# displays all books in host's book_arr in json formatting
@app.route('/book/arr', methods=['GET'])
def book_arr():
    response = {
        'book_arr_length': len(booklib.book_arr) ,
        'books': booklib.show_books()
    }
    return jsonify(response), 200

# sets current book
@app.route('/book/set', methods=['POST'])
def set_book():
    values = request.get_json()
    required = ['title']
    if not all(k in values for k in required):
        return 'Missing values', 400

    booklib.set_current_book(values['title'])

    response = {
        'current book': booklib.current_book 
    }
    return 'book has been set', 201
    

# adds new book onto host's book_arr and broadcasts book to update all other user's book_arr 
@app.route('/book/new', methods=['POST'])
def new_book():
    
    values = request.get_json()
    required = ['title']
    if not all(k in values for k in required):
        return 'Missing values', 400
    if not booklib.is_empty() and booklib.if_exists(values['title']):
        response = {
            'message' : 'this book already exists',
        }
        return jsonify(response), 400
    hosturl = request.host
    book = Blockchain(values['title'],hosturl)
    book.nodes = booklib.nodes
    booklib.book_arr.append(book)
    booklib.set_current_book(values['title'])
    booklib.resolve_books()

    neighboors = booklib.nodes
    for node in neighboors:
        response = requests.post(f'http://{node}/book/set', json={'title':values['title']})
    
    response = {
        'message' : 'A new book has been added!',
        'books': [x.title for x in booklib.book_arr]
    }
    return jsonify(response), 201

# checks if user's address is legitimate
@app.route('/verifyID', methods=['POST'])
def verifyID():
    values = request.get_json()
    if(booklib.verify_address(values['ID']['public_key'],values['ID']['book_index'],values['ID']['address_signature'])):
        return  'verified user ',201
    return 'not verified user',400
    
# pings target user to broadcast its serialized public key and address to have it verified
# pings target user to set current book of all users to requested book and add a new block
# pings target user to ping all the other users to update blockchain
@app.route('/ping',methods=['POST'])
def ping():
    values = request.get_json()
    # broadcast public key and address
    if(booklib.broadcast_address(booklib.findBook(values["title"]), values['hosturl'])):
        neighboors = booklib.nodes
        for node in neighboors:
            response = requests.post(f'http://{node}/book/set', json={'title':values['title']})
        booklib.set_current_book(values['title'])
        # new block being formed
        booklib.current_book.new_transaction(f'http://{request.host}',f"http://{values['hosturl']}")
        proof = booklib.current_book.proof_of_work(booklib.current_book.last_block)
        previous_hash = booklib.current_book.hash(booklib.current_book.last_block)
        


        # where verification of the transaction takes place vvvvvvvvv
        booklib.temp_block = {
            'index': len(booklib.current_book.chain),
            'transactions': booklib.current_book.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash ,
        }

        print('\n\n1) in ping route:\n\nhash of the block is: ->',booklib.hashValues(len(booklib.current_book.chain), proof, previous_hash), '<- this is a hash of the temp block\n\n')
        print('\n\nhosturl: ', values['hosturl'], '\n\n\n')
        print('\n\n\nthis is the temp blockchain ', json.dumps(booklib.temp_block),'\n\n\n\n\n')
        
        response = requests.post(f'http://{values["hosturl"]}/receive/hash', json = { 'hash' : booklib.hashValues(len(booklib.current_book.chain), proof, previous_hash), 'ownerurl': request.host })
        booklib.temp_block = {}
        print('\n\n7) returned back to ping route:\n\nthis is the temp blockchain ', json.dumps(booklib.temp_block),'\n\n\n\n\n')

        if(response.status_code == 201): # if transaction is verified and the owner has reliquished his ownership to the requestor mine block and mass consensus
            booklib.current_book.new_block(proof, previous_hash)
            
            # updates all other users current book
            booklib.mass_consensus()

            return f'sender [{request.url}] is verified', 201
    return 'sender is not verified', 400



# hash is received by the requestor
# and the requestor distributes the merged hash to verify it
@app.route('/receive/hash', methods=['POST'])
def receive_hash():
    values = request.get_json()
    print(f'\n\n2) in receive hash route:\n\nthis is node: {request.host}, this node received the hash {values["hash"]}\n\n\n\n')
    merged_hash = booklib.updateChainHash(values['hash'])
    print(f'\n\n\n merged hash is this:   {merged_hash} \n\n\n\n')
    if(booklib.distributeHash(merged_hash,values['ownerurl'])):
        return 'verified transaction', 201



    return 'wrong hash', 400

# for the nodes not involved in the transaction
# receives the data given by requestor
# requests the temp_block created by the host to relinquish ownership
# the nodes then try to recreate the hash from the requestor with the hash of their own 
# respective blockchain and the hash of the block received from the sender
# if they are able to recreate it then the transaction is legitimate
@app.route('/verify/hash', methods=['POST'])
def verify_hash():
    values = request.get_json()

    print(f'\n\n3) in verify hash route:\n\n\n owner url is {values["owner_url"]}.  this is from verify hash route and this is the hash received {values["blockchain_hash"]}')
    response = requests.get(f'http://{values["owner_url"]}/send/temp_block')
    if(response.status_code == 200):
        temp_block = response.json()['temp_block']
        temp_block_hash = booklib.hashValues(temp_block['index'],temp_block['proof'],temp_block['previous_hash'])
        print(f'\n\n\n5) returned to verify hash route:\n\n\n\nreceived temp_block: this is it \n {json.dumps(temp_block)} \n\n and this is the hash: {temp_block_hash}\n\n\n\n')
        blockchain_hash = booklib.updateChainHash(temp_block_hash)
        
        if(blockchain_hash == values['blockchain_hash']):
            print(f'\n\n\n\n6) transaction has been verified:\n\n\n\n http://{request.host} blockchain_hash: {blockchain_hash}\n\n requestor\'s blockchain_hash: {values["blockchain_hash"]}\n\n\n\n\n')
            return 'hash verified', 201
    return 'not verified', 400

# send the temp block to whoever request it
@app.route('/send/temp_block', methods=['GET'])
def send_block_values():
    print(f'\n\n4) in send temp block route\n\n')
    response = {
        'temp_block': booklib.temp_block
    }
    return jsonify(response), 200
# new route ^^^^^^



# requests book and changes ownership
# makes sure host is not the current owner of the book
# if that is the case then nothing is done and the request is void
# broadcasts users, who are making the transaction, info to verify that they are a legitamate user
# returns message on successfull request
# returns error in verification message if verification process fails
# if the host is the owner checks if the book even exists in host's book_arr
# if target book doesn't exist then return error-case message
# if host is the owner of target book and book exist, return error-case message
@app.route('/book/request', methods=['POST'])
def request_book():
    
    values = request.get_json()
    required = ['title']
    if not all(k in values for k in required):
        return 'Missing values', 400

    
    owner = booklib.find_owner(values['title'])
    neighboors = booklib.nodes
    if( (owner != f'http://{request.host}') and (owner != 'book doesn\'t exist')):
        if(booklib.ping_node(owner,values['title'],request.host)):
            message = {
                'verification': 'sender and recipient are verified',
                'message':'book has been successfully requested',
                'former owner': owner,
                'new owner':f'http://{request.host}'
            }
            return jsonify(message), 201
    
        message = {
            'verification':'either recipient or sender are not verifiable',
            'message': 'book request is void'
        }
        return jsonify(message), 400
        

    if(booklib.if_exists(values['title']) == False):
        message = {
            'message': f'{values["title"]} doesn\'t exist'
        }
        return jsonify(message), 400
    else:
        message = {
            'message': 'request cannot be made because you are the owner'
        }
        return jsonify(message), 400

# display info on current book of host's current book
@app.route('/chain', methods=['GET'])
def full_chain():
    public_key = booklib.current_book.private_key.public_key()
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    response = {
        'book title': booklib.current_book.title,
        'bookchain': booklib.current_book.chain,
        'signature': booklib.current_book.get_signature(),
        'public_key': serialized_public_key.hex(),
        'length': len(booklib.current_book.chain)
    }
    return jsonify(response), 200

# parses and adds nodes to host's log of nodes
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        booklib.add_book_nodes(node)
        

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(booklib.nodes),
    }
    return jsonify(response), 201

# makes sure host's current book's chain is up to date
# updates current book chain
@app.route('/nodes/resolve', methods=['POST'])
def consensus():
    replaced = booklib.current_book.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': booklib.current_book.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': booklib.current_book.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)
  
