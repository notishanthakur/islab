"""
Menu-driven OO skeleton with in-memory dictionaries.
Student -> AES encrypt + hash
Teacher -> AES decrypt + hash compare
HOD -> view all transactions and verify
"""

import os
import hashlib
import time
from datetime import datetime
import matplotlib.pyplot as plt

# ---------------------------
# ---- Hook your algorithms
# ---------------------------
try:
    from Algorithms.aes_128 import encrypt as aes_encrypt, decrypt as aes_decrypt
except Exception:
    def aes_encrypt(key_bytes: bytes, plaintext_bytes: bytes) -> bytes:
        raise NotImplementedError("Provide aes_encrypt(key_bytes, plaintext_bytes)")
    def aes_decrypt(key_bytes: bytes, ciphertext_bytes: bytes) -> bytes:
        raise NotImplementedError("Provide aes_decrypt(key_bytes, ciphertext_bytes)")

try:
    from Algorithms.elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt
except Exception:
    def elgamal_keygen(*args, **kwargs):
        raise NotImplementedError("Provide elgamal_keygen")
    def elgamal_encrypt(*args, **kwargs):
        raise NotImplementedError("Provide elgamal_encrypt")
    def elgamal_decrypt(*args, **kwargs):
        raise NotImplementedError("Provide elgamal_decrypt")

try:
    from Algorithms.sha import sha256
except Exception:
    def sha256(msg: str) -> str:
        return hashlib.sha256(msg.encode()).hexdigest()

# ---------------------------
# ---- Global in-memory storage
# ---------------------------
KEYS_STORE = {}       # username -> dict of keys
TRANSACTIONS = []     # list of dicts with sender/receiver/hash/timestamp/message preview

# ---------------------------
# ---- Utilities
# ---------------------------
def now_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def derive_aes_key_from_secret(secret_int, key_len_bytes=16):
    s = str(secret_int).encode()
    return hashlib.sha256(s).digest()[:key_len_bytes]

# ---------------------------
# ---- Users
# ---------------------------
class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.keys = {}  # algorithm keys
        KEYS_STORE[self.username] = self.keys

class Student(User):
    def __init__(self, username):
        super().__init__(username, "student")

    def create_aes_key(self):
        key = os.urandom(16)
        self.keys["aes"] = key
        return key

    def encrypt_and_send(self, plaintext: str, teacher_pub_elgamal, elgamal_params):
        aes_key = self.create_aes_key()
        ciphertext = aes_encrypt(aes_key, plaintext.encode())
        hash_hex = sha256(plaintext)
        key_blob = aes_key + b"::" + hash_hex.encode()
        encrypted_key_blob = elgamal_encrypt(key_blob, teacher_pub_elgamal, elgamal_params)
        # store transaction in memory
        TRANSACTIONS.append({
            "timestamp": now_timestamp(),
            "sender": self.username,
            "receiver": "teacher",
            "hash": hash_hex,
            "preview": plaintext[:100]
        })
        return {
            "ciphertext": ciphertext,
            "encrypted_key_blob": encrypted_key_blob,
            "hash": hash_hex
        }

class Teacher(User):
    def __init__(self, username):
        super().__init__(username, "teacher")

    def receive_and_decrypt(self, package, my_elgamal_priv, elgamal_params):
        ciphertext = package["ciphertext"]
        key_blob = elgamal_decrypt(package["encrypted_key_blob"], my_elgamal_priv, elgamal_params)
        aes_key, sent_hash_hex = key_blob.split(b"::")
        sent_hash_hex = sent_hash_hex.decode()
        plaintext = aes_decrypt(aes_key, ciphertext).decode()
        computed_hash = sha256(plaintext)
        valid = computed_hash == sent_hash_hex
        # store transaction
        TRANSACTIONS.append({
            "timestamp": now_timestamp(),
            "sender": "teacher",
            "receiver": package.get("sender", "unknown"),
            "hash": computed_hash,
            "preview": plaintext[:100]
        })
        return {"plaintext": plaintext, "valid": valid, "computed_hash": computed_hash, "sent_hash": sent_hash_hex}

class HOD(User):
    def __init__(self, username="hod"):
        super().__init__(username, "hod")

    def view_transactions(self):
        print("\n--- Transactions ---")
        for i, t in enumerate(TRANSACTIONS, 1):
            print(f"{i}. [{t['timestamp']}] {t['sender']} -> {t['receiver']} | hash: {t['hash']} | preview: {t['preview']}")
        print("--- End ---\n")

    def verify_transaction(self, idx, original_plaintext=None):
        if idx <=0 or idx > len(TRANSACTIONS):
            print("Invalid index")
            return
        t = TRANSACTIONS[idx-1]
        if not original_plaintext:
            print(f"Stored hash: {t['hash']}")
            return
        new_hash = sha256(original_plaintext)
        print("Verification result:", new_hash == t['hash'])

    def plot_transactions(self):
        if not TRANSACTIONS:
            print("No transactions to plot")
            return
        timestamps = [datetime.strptime(t["timestamp"], "%Y-%m-%d %H:%M:%S") for t in TRANSACTIONS]
        senders_count = {}
        for t in TRANSACTIONS:
            senders_count[t["sender"]] = senders_count.get(t["sender"],0)+1

        # Cumulative over time
        timestamps_sorted = sorted(timestamps)
        counts = list(range(1,len(timestamps_sorted)+1))
        plt.figure(figsize=(10,4))
        plt.plot(timestamps_sorted, counts, marker="o")
        plt.title("Cumulative Transactions Over Time")
        plt.xlabel("Time")
        plt.ylabel("Count")
        plt.grid(True)
        plt.show()

        # Bar chart per sender
        plt.figure(figsize=(6,4))
        plt.bar(list(senders_count.keys()), list(senders_count.values()))
        plt.title("Transactions per sender")
        plt.show()

# ---------------------------
# ---- Menu
# ---------------------------
def demo_key_setup():
    try:
        p, g = 467, 2
        teacher_pub, teacher_priv = elgamal_keygen(p,g)
        return teacher_pub, teacher_priv, {"p":p,"g":g}
    except:
        print("Adapt demo_key_setup for your elgamal API")
        return None, None, None

def main_menu():
    student = Student("alice")
    teacher = Teacher("prof_bob")
    hod = HOD("hod")
    teacher_pub, teacher_priv, elgamal_params = demo_key_setup()

    while True:
        print("\n--- Main Menu ---")
        print("1. Student: Encrypt & send")
        print("2. Teacher: Receive & decrypt")
        print("3. HOD: View / verify / plot")
        print("4. Exit")
        choice = input("Choice: ").strip()
        if choice=="1":
            msg = input("Enter message: ")
            pkg = student.encrypt_and_send(msg, teacher_pub, elgamal_params)
            print("Message encrypted and sent in memory.")
        elif choice=="2":
            if not TRANSACTIONS:
                print("No message from student yet")
                continue
            # for demo, use last student package (could store in a variable)
            pkg = student.encrypt_and_send("Temp", teacher_pub, elgamal_params)  # placeholder
            result = teacher.receive_and_decrypt(pkg, teacher_priv, elgamal_params)
            print("Decrypted:", result["plaintext"])
            print("Signature valid:", result["valid"])
        elif choice=="3":
            while True:
                print("\nHOD Menu:\n1. View\n2. Verify\n3. Plot\n4. Back")
                ch = input("Choice: ").strip()
                if ch=="1":
                    hod.view_transactions()
                elif ch=="2":
                    idx = int(input("Enter transaction index: "))
                    orig = input("Enter original plaintext (optional): ")
                    hod.verify_transaction(idx, orig if orig else None)
                elif ch=="3":
                    hod.plot_transactions()
                elif ch=="4":
                    break
                else:
                    print("Invalid")
        elif choice=="4":
            break
        else:
            print("Invalid choice")

if __name__=="__main__":
    main_menu()
