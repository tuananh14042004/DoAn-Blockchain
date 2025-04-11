import hashlib
import json
from time import time

class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        # Tạo block genesis
        self.create_block(previous_hash='1')

    def create_block(self, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.transactions,
            'previous_hash': previous_hash,
            'nonce': 0,
            'hash': ''
        }
        # Proof of Work (giả lập đơn giản)
        block['hash'] = self.hash_block(block)
        self.chain.append(block)
        self.transactions = []  # Reset transactions sau khi tạo block
        return block

    def add_transaction(self, sender, receiver, amount, transaction_name):
        self.transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount,
            'transaction_name': transaction_name  # Thêm trường mới
        })

    def get_all_transactions(self):
        # Trả về tất cả giao dịch, bao gồm cả trong chain và transactions chưa được đào
        all_transactions = []
        for block in self.chain:
            all_transactions.extend(block['transactions'])
        all_transactions.extend(self.transactions)
        return all_transactions

    def hash_block(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]