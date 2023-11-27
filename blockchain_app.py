from flask import Flask, request, jsonify
import hashlib
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, hash, public_key, signature):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.hash = hash
        self.public_key = public_key
        self.signature = signature

def calculate_hash(index, previous_hash, timestamp, transactions, public_key):
    value = str(index) + str(previous_hash) + str(timestamp) + str(transactions) + str(public_key)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    return private_key.sign(data.encode('utf-8'),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256())

def verify_signature(public_key, signature, data):
    public_key.verify(
        signature,
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def create_genesis_block(private_key):
    index = 0
    previous_hash = "0"
    timestamp = time.time()
    transactions = []
    public_key = private_key.public_key()
    hash_value = calculate_hash(index, previous_hash, timestamp, transactions, public_key)
    signature = sign_data(private_key, hash_value)

    return Block(index, previous_hash, timestamp, transactions, hash_value, public_key, signature)

def create_new_block(previous_block, private_key, transactions):
    index = previous_block.index + 1
    timestamp = time.time()
    public_key = private_key.public_key()
    hash_value = calculate_hash(index, previous_block.hash, timestamp, transactions, public_key)
    signature = sign_data(private_key, hash_value)

    return Block(index, previous_block.hash, timestamp, transactions, hash_value, public_key, signature)

private_key1, public_key1 = generate_key_pair()
blockchain = [create_genesis_block(private_key1)]
previous_block = blockchain[0]

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    data = request.get_json()
    new_transaction = data.get('transaction')
    
    new_block = create_new_block(previous_block, private_key1, [new_transaction])
    blockchain.append(new_block)
    previous_block = new_block

    response = {
        'message': f'Transaction added to Block #{new_block.index}',
        'block_hash': new_block.hash
    }

    return jsonify(response)

@app.route('/get_blockchain', methods=['GET'])
def get_blockchain():
    response = {
        'blockchain': [
            {
                'index': block.index,
                'hash': block.hash,
                'timestamp': block.timestamp,
                'transactions': block.transactions,
                'public_key': block.public_key,
                'signature': block.signature
            } for block in blockchain
        ]
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
