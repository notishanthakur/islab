"""
menu_system.py

Menu-driven OO skeleton for Student / Teacher / HOD workflow.

Assumptions:
- You have an Algorithms package (folder `Algorithms`) with functions for:
    AES:  encrypt_aes(key: bytes, plaintext: bytes) -> bytes
          decrypt_aes(key: bytes, ciphertext: bytes) -> bytes
    ElGamal: elgamal_keygen(p, g) -> (pub, priv) or similar
             elgamal_encrypt(m: bytes, pub, params) -> bytes
             elgamal_decrypt(ciphertext: bytes, priv, params) -> bytes
    RSA: rsa_encrypt(...), rsa_decrypt(...), etc.
    Hash: sha256(msg: str) -> hex str (you also have sha128/sha512 if needed)

If your function names differ, adapt the wrapper functions below.
"""

import json
import csv
import os
import time
from datetime import datetime
import hashlib
import matplotlib.pyplot as plt

# ---------------------------
# ---- Hook your algorithms
# ---------------------------
# Edit these imports to match your Algorithms package file/module names.
# Example structure you've used earlier:
# from Algorithms import modularinverse, rsa_encrypt, rsa_decrypt, ...
#
# Here we try to import common names; if not present we raise a clear error
# telling you which wrapper to edit.

try:
    # AES functions (expected to be provided by you)
    # Implementations expected:
    #   aes_encrypt(key_bytes: bytes, plaintext_bytes: bytes) -> bytes
    #   aes_decrypt(key_bytes: bytes, ciphertext_bytes: bytes) -> bytes
    from Algorithms.aes_128 import encrypt as aes_encrypt, decrypt as aes_decrypt
except Exception as e:
    # If your aes module uses different names, change these wrapper functions below.
    def aes_encrypt(key_bytes: bytes, plaintext_bytes: bytes) -> bytes:
        raise ImportError("Please implement aes_encrypt(key_bytes, plaintext_bytes) or adjust imports. " 
                          "Currently Algorithms.aes_128.encrypt not found.")
    def aes_decrypt(key_bytes: bytes, ciphertext_bytes: bytes) -> bytes:
        raise ImportError("Please implement aes_decrypt(key_bytes, ciphertext_bytes) or adjust imports.")


try:
    # ElGamal style API (adjust if you named differently)
    # Expected:
    #   elgamal_keygen(p, g) -> (public_key, private_key) or a tuple/structure you use
    #   elgamal_encrypt(bytes_data, public_key, params...) -> bytes or tuple
    #   elgamal_decrypt(ciphertext, private_key, params...) -> bytes
    from Algorithms.elgamal import elgamal_keygen, elgamal_encrypt, elgamal_decrypt
except Exception:
    # Provide placeholder wrappers to help you adapt names:
    def elgamal_keygen(*args, **kwargs):
        raise ImportError("Please implement elgamal_keygen or adjust imports in this file.")
    def elgamal_encrypt(*args, **kwargs):
        raise ImportError("Please implement elgamal_encrypt or adjust imports in this file.")
    def elgamal_decrypt(*args, **kwargs):
        raise ImportError("Please implement elgamal_decrypt or adjust imports in this file.")


try:
    # Hash functions: sha256, sha128/sha512 optional
    from Algorithms.sha import sha256, sha128, sha512
except Exception:
    # fallback implementations using hashlib
    def sha256(message: str) -> str:
        return hashlib.sha256(message.encode()).hexdigest()
    def sha512(message: str) -> str:
        return hashlib.sha512(message.encode()).hexdigest()
    def sha128(message: str) -> str:
        # MD5 used as 128-bit placeholder
        return hashlib.md5(message.encode()).hexdigest()


# ---------------------------
# ---- Storage locations
# ---------------------------
RECORDS_CSV = "records.csv"   # tabular log (sender, receiver, hash, timestamp, preview)
RECORDS_TXT = "records.txt"   # human readable appended log
KEYS_JSON   = "keys.json"     # store public/private keys per user (simple JSON store)

# ensure csv file has headers if not exists
if not os.path.exists(RECORDS_CSV):
    with open(RECORDS_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "sender", "receiver", "hash_hex", "message_preview"])

# ensure keys.json exists
if not os.path.exists(KEYS_JSON):
    with open(KEYS_JSON, "w") as f:
        json.dump({}, f, indent=4)


# ---------------------------
# ---- Utility helpers
# ---------------------------
def save_record_csv(sender, receiver, hash_hex, message_preview):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(RECORDS_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([ts, sender, receiver, hash_hex, message_preview[:100]])
    # append to text log too
    with open(RECORDS_TXT, "a") as f:
        f.write(f"[{ts}] {sender} -> {receiver} : {hash_hex} : {message_preview[:200]}\n")


def load_keys():
    with open(KEYS_JSON, "r") as f:
        return json.load(f)


def save_keys(dct):
    with open(KEYS_JSON, "w") as f:
        json.dump(dct, f, indent=4, default=str)


def derive_aes_key_from_secret(secret_int, key_len_bytes=16):
    """
    Derive AES key bytes from a shared integer secret (e.g., DH or ElGamal numeric)
    We use SHA-256 and truncate. Returns bytes.
    """
    s = str(secret_int).encode()
    digest = hashlib.sha256(s).digest()
    return digest[:key_len_bytes]


def now_timestamp_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------
# ---- Domain objects
# ---------------------------
class MessageRecord:
    def __init__(self, sender, receiver, hash_hex, timestamp=None, preview=""):
        self.sender = sender
        self.receiver = receiver
        self.hash_hex = hash_hex
        self.timestamp = timestamp or now_timestamp_str()
        self.preview = preview

    def to_csv_row(self):
        return [self.timestamp, self.sender, self.receiver, self.hash_hex, self.preview[:100]]


class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role  # 'student', 'teacher', 'hod'
        self.keys = {}    # store algorithm keys (e.g., AES keys, RSA keys, ElGamal keys)
        # In practice store these securely. Here we persist to keys.json for convenience.

    def save_keys_to_store(self):
        store = load_keys()
        store[self.username] = {"role": self.role, "keys": self.keys}
        save_keys(store)

    def load_keys_from_store(self):
        store = load_keys()
        data = store.get(self.username)
        if not data:
            return False
        self.role = data["role"]
        self.keys = data["keys"]
        return True


class Student(User):
    def __init__(self, username):
        super().__init__(username, "student")

    def create_aes_key(self):
        """
        Student generates a random AES key (bytes).
        In real code: use secure random. Here we use os.urandom for AES key.
        """
        key = os.urandom(16)  # AES-128 by default. Swap to 24/32 for AES-192/256
        self.keys["aes_key"] = key.hex()
        self.save_keys_to_store()
        return key

    def encrypt_and_send(self, plaintext: str, teacher_public_elgamal, elgamal_params):
        """
        Steps:
        1. create AES key
        2. encrypt plaintext with AES
        3. compute hash (sha256) of plaintext -> signature_data
        4. sign or encrypt the hash (we will encrypt the hash using student's private key in RSA-style
           if you have RSA sign function; in this template we'll send the hash itself and then
           encrypt AES key+hash using ElGamal to teacher)
        5. encrypt the AES key + signature with teacher's ElGamal public key
        6. store logs and return the package (ciphertext, encrypted_key_blob)
        """

        # 1. AES key
        aes_key = self.create_aes_key()   # bytes

        # 2. AES encrypt the plaintext (we expect aes_encrypt -> bytes)
        plaintext_bytes = plaintext.encode()
        ciphertext = aes_encrypt(aes_key, plaintext_bytes)  # bytes expected

        # 3. compute hash of plaintext (hex string)
        hash_hex = sha256(plaintext)

        # 4. create message preview for logs
        preview = plaintext[:200]

        # 5. Prepare key+signature blob: we will pack aes_key + hash_hex
        #    Format: aes_key_bytes || b"::" || hash_hex.encode()
        #    You may choose a better serialization (JSON + bytes) in real code.
        key_blob = aes_key + b"::" + hash_hex.encode()

        # 6. Encrypt key_blob to teacher using ElGamal public key (user supplies teacher_public_elgamal)
        #    You must adapt this call to your elgamal API. We keep it abstract here.
        #    Expect elgamal_encrypt to return bytes or tuple (ciphertext, extra)
        encrypted_key_blob = elgamal_encrypt(key_blob, teacher_public_elgamal, elgamal_params)

        # 7. Save record to CSV/TXT for HOD
        save_record_csv(self.username, "teacher", hash_hex, preview)

        # 8. Return package to send over network / saved to disk
        package = {
            "sender": self.username,
            "ciphertext": ciphertext.hex(),            # store hex to simplify JSON transport
            "encrypted_key_blob": serialized(encrypted_key_blob),
            "hash_hex": hash_hex,
            "timestamp": now_timestamp_str()
        }
        return package


class Teacher(User):
    def __init__(self, username):
        super().__init__(username, "teacher")

    def receive_and_decrypt(self, package, my_elgamal_priv, elgamal_params):
        """
        1. decrypt encrypted_key_blob using my_elgamal_priv -> get aes_key + signature/hash
        2. use aes_key to decrypt ciphertext
        3. compute hash and compare with signature/hash sent by student
        4. record the result and return
        """
        # Parse package
        ciphertext_bytes = bytes.fromhex(package["ciphertext"])
        encrypted_blob = deserialized(package["encrypted_key_blob"])

        # Decrypt key blob using teacher private ElGamal key
        key_blob = elgamal_decrypt(encrypted_blob, my_elgamal_priv, elgamal_params)
        # key_blob expected format: aes_key_bytes + b"::" + hash_hex_bytes
        if isinstance(key_blob, tuple) or isinstance(key_blob, list):
            # Some elgamal implementations return structures - adapt accordingly
            key_blob = key_blob[0]

        # Ensure bytes
        if isinstance(key_blob, str):
            key_blob = key_blob.encode()

        try:
            aes_key, sent_hash_hex = key_blob.split(b"::")
            sent_hash_hex = sent_hash_hex.decode()
        except Exception:
            raise ValueError("Unexpected key_blob format. Update parsing to match your elgamal output.")

        # Decrypt AES ciphertext
        plaintext_bytes = aes_decrypt(aes_key, ciphertext_bytes)
        plaintext = plaintext_bytes.decode()

        # Compute hash locally and compare
        computed_hash = sha256(plaintext)
        match = computed_hash == sent_hash_hex

        # Save record (teacher side)
        save_record_csv("teacher", package["sender"], computed_hash, plaintext[:200])

        return {
            "plaintext": plaintext,
            "sent_hash": sent_hash_hex,
            "computed_hash": computed_hash,
            "valid": match
        }


class HOD(User):
    def __init__(self, username="hod"):
        super().__init__(username, "hod")

    def view_all_records(self):
        # Print CSV file contents in human-friendly form
        print("\n--- All Transactions (records.csv) ---")
        with open(RECORDS_CSV, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                print(", ".join(row))
        print("--- End of Records ---\n")

    def verify_record(self, row_index):
        """
        Verify a record at row_index (1-based excluding header).
        This just recomputes the hash of the preview or asks user to provide original plaintext.
        """
        with open(RECORDS_CSV, "r") as f:
            reader = list(csv.reader(f))
        header = reader[0]
        if row_index <= 0 or row_index >= len(reader):
            print("Invalid index")
            return False
        row = reader[row_index]
        ts, sender, receiver, hash_hex, preview = row
        print(f"Record: {row}")
        # HOD cannot fully verify without original plaintext; ask for it:
        original = input("Provide original plaintext (or press enter to skip): ")
        if not original:
            print("No plaintext provided; cannot fully verify. Hash saved:")
            print(hash_hex)
            return None
        recomputed = sha256(original)
        ok = recomputed == hash_hex
        print("Verification result:", ok)
        return ok

    def plot_transactions(self):
        """
        Plot number of transactions over time and a bar chart per sender
        """
        timestamps = []
        senders = {}
        with open(RECORDS_CSV, "r") as f:
            reader = list(csv.reader(f))
            for i, row in enumerate(reader[1:], start=1):
                ts_str, sender, receiver, hash_hex, preview = row
                timestamps.append(datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
                senders[sender] = senders.get(sender, 0) + 1

        if not timestamps:
            print("No transactions to plot.")
            return

        # Time series: cumulative transactions
        timestamps_sorted = sorted(timestamps)
        counts = list(range(1, len(timestamps_sorted) + 1))

        plt.figure(figsize=(10, 4))
        plt.plot(timestamps_sorted, counts, marker="o")
        plt.title("Cumulative Transactions Over Time")
        plt.xlabel("Time")
        plt.ylabel("Cumulative count")
        plt.grid(True)
        plt.tight_layout()
        plt.show()

        # Bar chart per sender
        plt.figure(figsize=(6, 4))
        plt.bar(list(senders.keys()), list(senders.values()))
        plt.title("Transactions by Sender")
        plt.xlabel("Sender")
        plt.ylabel("Number of transactions")
        plt.tight_layout()
        plt.show()


# ---------------------------
# ---- Serialization helpers
# ---------------------------
def serialized(obj):
    """
    Convert an object returned by elgamal_encrypt to a JSON-safe string.
    If your elgamal returns bytes: return hex; if tuple: json-serialize.
    Adapt this function to your elgamal implementation.
    """
    # simple attempt:
    if obj is None:
        return None
    if isinstance(obj, bytes):
        return {"type": "bytes", "data": obj.hex()}
    if isinstance(obj, str):
        return {"type": "str", "data": obj}
    if isinstance(obj, (list, tuple)):
        # try to convert elements
        out = []
        for e in obj:
            if isinstance(e, bytes):
                out.append({"type": "bytes", "data": e.hex()})
            elif isinstance(e, str):
                out.append({"type": "str", "data": e})
            else:
                out.append({"type": "repr", "data": repr(e)})
        return {"type": "list", "data": out}
    # fallback
    return {"type": "repr", "data": repr(obj)}


def deserialized(obj):
    """
    Undo serialized -> return bytes or str or list. Keep in sync with serialized().
    """
    if obj is None:
        return None
    if isinstance(obj, dict) and "type" in obj:
        t = obj["type"]
        if t == "bytes":
            return bytes.fromhex(obj["data"])
        if t == "str":
            return obj["data"]
        if t == "list":
            out = []
            for item in obj["data"]:
                if item["type"] == "bytes":
                    out.append(bytes.fromhex(item["data"]))
                elif item["type"] == "str":
                    out.append(item["data"])
                else:
                    out.append(item["data"])
            return out
        if t == "repr":
            return obj["data"]
    return obj


# ---------------------------
# ---- Menu / CLI
# ---------------------------
def demo_key_setup():
    """
    Generate a sample ElGamal keypair for teacher and store in keys.json
    Adjust/eliminate if you already manage keys differently.
    """
    # elgamal_keygen params depend on your implementation; here we call generically.
    # Example: elgamal_keygen(p, g) -> (pub, priv)
    try:
        # Example params - replace with real secure params
        p = 467
        g = 2
        teacher_pub, teacher_priv = elgamal_keygen(p, g)
        # store in keys.json under 'teacher'
        store = load_keys()
        store["teacher_elgamal"] = {"pub": repr(teacher_pub), "priv": repr(teacher_priv), "params": {"p": p, "g": g}}
        save_keys(store)
        print("Demo ElGamal keys generated for 'teacher' (edit as needed).")
        return (teacher_pub, teacher_priv, {"p": p, "g": g})
    except Exception as e:
        print("demo_key_setup: could not create keys automatically. Edit this function to match your elgamal API.")
        print("Error:", e)
        return (None, None, None)


def main_menu():
    # Create demo users for the session (in a real program you'd have authentication)
    student = Student("alice")
    teacher = Teacher("prof_bob")
    hod = HOD("hod")

    # Optionally create demo elgamal keys (you should replace this with your key distribution)
    teacher_pub, teacher_priv, elgamal_params = demo_key_setup()

    while True:
        print("\n--- Main Menu ---")
        print("1. Student: Encrypt & send")
        print("2. Teacher: Receive & decrypt")
        print("3. HOD: View records / verify / plot")
        print("4. Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            # Student action
            plaintext = input("Enter message to encrypt (student): ")
            # Student packages ciphertext + encrypted key blob for teacher
            try:
                package = student.encrypt_and_send(plaintext, teacher_pub, elgamal_params)
                # Save package to a temporary file representing 'sent message'
                with open("last_package.json", "w") as f:
                    json.dump(package, f, indent=2)
                print("Message encrypted and package saved to last_package.json")
            except Exception as e:
                print("Encryption/send failed. Check your algorithm hooks. Error:", e)

        elif choice == "2":
            # Teacher action: read last package and decrypt
            if not os.path.exists("last_package.json"):
                print("No package to receive (last_package.json missing). Student must send first.")
                continue
            with open("last_package.json", "r") as f:
                package = json.load(f)
            # Use teacher_priv and elgamal_params from demo_key_setup (or load real keys)
            try:
                result = teacher.receive_and_decrypt(package, teacher_priv, elgamal_params)
                print("Decryption result:")
                print("Plaintext:", result["plaintext"])
                print("Sent hash:", result["sent_hash"])
                print("Computed hash:", result["computed_hash"])
                print("Signature valid:", result["valid"])
            except Exception as e:
                print("Decryption/verification failed. Error:", e)

        elif choice == "3":
            # HOD menu
            while True:
                print("\n--- HOD Menu ---")
                print("1. View all records")
                print("2. Verify a record by index")
                print("3. Plot transactions")
                print("4. Back")
                ch = input("Choice: ").strip()
                if ch == "1":
                    hod.view_all_records()
                elif ch == "2":
                    idx = int(input("Enter row index (1-based, header is row 0): "))
                    hod.verify_record(idx)
                elif ch == "3":
                    hod.plot_transactions()
                elif ch == "4":
                    break
                else:
                    print("Invalid choice")
        elif choice == "4":
            print("Exiting.")
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main_menu()
