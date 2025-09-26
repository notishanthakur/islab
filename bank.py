import os
import hashlib
from datetime import datetime
import matplotlib.pyplot as plt

# Hook your algorithms
try:
    from Algorithms.aes_128 import encrypt as aes_encrypt, decrypt as aes_decrypt
except Exception:
    def aes_encrypt(key, plaintext_bytes): raise NotImplementedError()
    def aes_decrypt(key, ciphertext_bytes): raise NotImplementedError()

try:
    from Algorithms.elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt
except Exception:
    def elgamal_keygen(*args, **kwargs): raise NotImplementedError()
    def elgamal_encrypt(*args, **kwargs): raise NotImplementedError()
    def elgamal_decrypt(*args, **kwargs): raise NotImplementedError()

# ---------------------------
# In-memory storage
# ---------------------------
ACCOUNTS = {}      # username -> {balance, keys}
TRANSACTIONS = []  # list of dicts: sender, receiver, amount, timestamp, hash

# ---------------------------
# Utilities
# ---------------------------
def now_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256(msg: str):
    return hashlib.sha256(msg.encode()).hexdigest()

def derive_aes_key(secret_int, key_len=16):
    return hashlib.sha256(str(secret_int).encode()).digest()[:key_len]

# ---------------------------
# Users
# ---------------------------
class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.keys = {}
        ACCOUNTS[self.username] = {"balance": 0, "keys": self.keys}

class Customer(User):
    def __init__(self, username):
        super().__init__(username, "customer")

    def create_aes_key(self):
        key = os.urandom(16)
        self.keys["aes"] = key
        return key

    def make_transaction(self, amount, receiver, bank_pub_elgamal, elgamal_params):
        key = self.create_aes_key()
        transaction = f"{self.username}->{receiver}:{amount}"
        ciphertext = aes_encrypt(key, transaction.encode())
        tx_hash = sha256(transaction)
        key_blob = key + b"::" + tx_hash.encode()
        encrypted_key_blob = elgamal_encrypt(key_blob, bank_pub_elgamal, elgamal_params)
        TRANSACTIONS.append({
            "timestamp": now_timestamp(),
            "sender": self.username,
            "receiver": receiver,
            "amount": amount,
            "hash": tx_hash,
            "preview": transaction[:50]
        })
        return {"ciphertext": ciphertext, "encrypted_key_blob": encrypted_key_blob, "hash": tx_hash}

class Bank(User):
    def __init__(self, username="bank"):
        super().__init__(username, "bank")

    def process_transaction(self, package, priv_elgamal, elgamal_params):
        key_blob = elgamal_decrypt(package["encrypted_key_blob"], priv_elgamal, elgamal_params)
        key, sent_hash = key_blob.split(b"::")
        sent_hash = sent_hash.decode()
        plaintext = aes_decrypt(key, package["ciphertext"]).decode()
        computed_hash = sha256(plaintext)
        valid = computed_hash == sent_hash
        # update balances if valid
        sender, rest = plaintext.split("->")
        receiver, amount = rest.split(":")
        amount = float(amount)
        if valid:
            ACCOUNTS[sender]["balance"] -= amount
            if receiver not in ACCOUNTS:
                ACCOUNTS[receiver] = {"balance":0, "keys":{}}
            ACCOUNTS[receiver]["balance"] += amount
        return {"plaintext": plaintext, "valid": valid, "computed_hash": computed_hash}

class Auditor(User):
    def __init__(self, username="auditor"):
        super().__init__(username, "auditor")

    def view_transactions(self):
        print("\n--- Transactions ---")
        for i, t in enumerate(TRANSACTIONS,1):
            print(f"{i}. [{t['timestamp']}] {t['sender']} -> {t['receiver']} | amount: {t['amount']} | hash: {t['hash']}")
        print("--- End ---\n")

    def plot_transactions(self):
        if not TRANSACTIONS:
            print("No transactions to plot")
            return
        amounts = [t["amount"] for t in TRANSACTIONS]
        senders = [t["sender"] for t in TRANSACTIONS]
        plt.figure(figsize=(8,4))
        plt.bar(range(len(amounts)), amounts, tick_label=senders)
        plt.title("Transaction amounts per sender")
        plt.show()

# ---------------------------
# Demo key setup (placeholder)
# ---------------------------
def demo_key_setup():
    try:
        p,g = 467,2
        bank_pub, bank_priv = elgamal_keygen(p,g)
        return bank_pub, bank_priv, {"p":p,"g":g}
    except:
        return None,None,None

# ---------------------------
# Menu
# ---------------------------
def main_menu():
    customer = Customer("alice")
    bank = Bank()
    auditor = Auditor()
    bank_pub, bank_priv, elgamal_params = demo_key_setup()

    while True:
        print("\n--- Menu ---")
        print("1. Customer: Make transaction")
        print("2. Bank: Process transaction")
        print("3. Auditor: View / Plot")
        print("4. Exit")
        choice = input("Choice: ").strip()
        if choice=="1":
            receiver = input("Receiver: ")
            amount = float(input("Amount: "))
            pkg = customer.make_transaction(amount, receiver, bank_pub, elgamal_params)
            print("Transaction created and stored in memory.")
        elif choice=="2":
            if not TRANSACTIONS:
                print("No transactions")
                continue
            # For demo, process last transaction
            last_pkg = customer.make_transaction(100, "bob", bank_pub, elgamal_params)  # placeholder
            result = bank.process_transaction(last_pkg, bank_priv, elgamal_params)
            print("Processed transaction:", result["plaintext"])
            print("Valid:", result["valid"])
        elif choice=="3":
            while True:
                print("\nAuditor Menu:\n1.View\n2.Plot\n3.Back")
                ch = input("Choice: ")
                if ch=="1":
                    auditor.view_transactions()
                elif ch=="2":
                    auditor.plot_transactions()
                elif ch=="3":
                    break
        elif choice=="4":
            break
        else:
            print("Invalid choice")

if __name__=="__main__":
    main_menu()
