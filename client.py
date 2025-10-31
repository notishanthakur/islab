#!/usr/bin/env python3
"""
Doctor/Auditor client (template).
Interactive menu for Doctor and Auditor roles.
Replace crypto placeholders in CRYPTO SWAP AREA with actual libs.
"""

import socket, json, time, uuid
from base64 import b64encode, b64decode
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9000

def send_recv(obj):
    s = socket.socket()
    s.connect((HOST, PORT))
    s.sendall((json.dumps(obj) + "\n").encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            break
    s.close()
    try:
        return json.loads(data.decode().strip())
    except:
        return None

# -------------------------
# CRYPTO SWAP AREA
# Replace these placeholders with real implementations using PyCryptodome or other libs
# -------------------------
def generate_keypair_client():
    """
    Generate keys on client side: RSA keypair, ElGamal keypair, Paillier keypair
    Return a dict of public keys and private holder if needed (client keeps private keys).
    """
    # Template: return dummy strings
    return {
        "rsa": "rsa_public_placeholder",
        "elgamal": "elg_public_placeholder",
        "paillier": "paillier_public_placeholder"
    }, {
        "rsa_priv": "rsa_priv_placeholder",
        "elg_priv": "elg_priv_placeholder",
        "paillier_priv": "paillier_priv_placeholder"
    }

def aes_encrypt_report_plaintext(plaintext_bytes):
    """
    Return (aes_key_encrypted_for_server, nonce_b64, tag_b64, ciphertext_b64)
    - aes_key_encrypted_for_server: RSA-encrypted AES key (base64 or other string)
    - For template, we will simply base64 the plaintext and mark AES key as 'mock'
    """
    ciphertext_b64 = b64encode(plaintext_bytes).decode()
    return "rsa_encrypted_aeskey_mock", "", "", ciphertext_b64

def elgamal_sign(priv_elgamal, message_bytes):
    """
    Return base64 signature blob
    """
    import base64
    return base64.b64encode(("SIGNED:" + message_bytes.decode()).encode()).decode()

def paillier_encrypt_department_keyword(pub_paillier, dept_plaintext):
    """
    Return encrypted representation string
    """
    return b64encode(dept_plaintext.encode()).decode()

def rsa_homomorphic_encrypt_amount(pub_rsa, amount_int):
    """
    Return encrypted amount (string)
    """
    # template: simply stringified
    return str(amount_int)

# -------------------------
# End CRYPTO SWAP AREA
# -------------------------

def doctor_menu():
    pubkeys, privs = generate_keypair_client()
    doctor_id = input("Doctor ID to register (unique): ").strip()
    dept = input("Department (plain): ").strip()
    dept_enc = paillier_encrypt_department_keyword(pubkeys["paillier"], dept)
    reg_msg = {
        "type": "REGISTER",
        "role": "doctor",
        "doctor_id": doctor_id,
        "public_keys": pubkeys,
        "dept_encrypted": dept_enc
    }
    print("Registering...")
    print(send_recv(reg_msg))

    while True:
        print("\nDoctor Menu:")
        print("1) Submit Report")
        print("2) Log Expense (privacy-preserved)")
        print("3) List my reports")
        print("4) Exit")
        c = input("> ").strip()
        if c == "1":
            rid = str(uuid.uuid4())[:8]
            content = input("Enter report text: ").strip().encode()
            aes_key_enc, nonce, tag, ciphertext_b64 = aes_encrypt_report_plaintext(content)
            timestamp = datetime.utcnow().isoformat()
            signature = elgamal_sign(privs["elg_priv"], (ciphertext_b64 + "|" + timestamp).encode())
            expense = input("Expense amount (int, for homomorphic encrypt): ").strip()
            expense_enc = rsa_homomorphic_encrypt_amount(pubkeys["rsa"], int(expense)) if expense else None
            msg = {
                "type": "SUBMIT_REPORT",
                "doctor_id": doctor_id,
                "report_id": rid,
                "aes_key_encrypted": aes_key_enc,
                "aes_iv_nonce": nonce,
                "aes_tag": tag,
                "report_ciphertext": ciphertext_b64,
                "signature": signature,
                "timestamp": timestamp,
                "expense_encrypted": expense_enc
            }
            print("Submitting report...")
            print(send_recv(msg))
        elif c == "2":
            amt = int(input("Expense amount: ").strip())
            enc = rsa_homomorphic_encrypt_amount(pubkeys["rsa"], amt)
            # Attach expense to a special "expense-only" report
            rid = "expense-" + str(uuid.uuid4())[:6]
            msg = {
                "type":"SUBMIT_REPORT",
                "doctor_id": doctor_id,
                "report_id": rid,
                "aes_key_encrypted": "", "aes_iv_nonce":"", "aes_tag":"", "report_ciphertext":"",
                "signature": elgamal_sign(privs["elg_priv"], (rid + "|" + str(time.time())).encode()),
                "timestamp": datetime.utcnow().isoformat(),
                "expense_encrypted": enc
            }
            print(send_recv(msg))
        elif c == "3":
            resp = send_recv({"type":"LIST_RECORDS"})
            print("Server reports:", resp)
        else:
            break

def auditor_menu():
    while True:
        print("\nAuditor Menu:")
        print("1) Search doctors by department keyword (privacy-preserving)")
        print("2) Sum all expenses (encrypted)")
        print("3) Sum per-doctor expenses")
        print("4) Verify report authenticity & timestamp")
        print("5) List records")
        print("6) Exit")
        c = input("> ").strip()
        if c == "1":
            q = input("Department keyword to search: ").strip()
            q_enc = b64encode(q.encode()).decode()  # in template our server uses base64
            resp = send_recv({"type":"AUDITOR_SEARCH_DEPT", "dept_query_encrypted": q_enc})
            print("Matches:", resp)
        elif c == "2":
            resp = send_recv({"type":"AUDITOR_SUM_EXPENSES", "mode":"all"})
            print("Encrypted sum:", resp)
        elif c == "3":
            did = input("Doctor ID: ").strip()
            resp = send_recv({"type":"AUDITOR_SUM_EXPENSES", "mode":"per_doctor", "doctor_id": did})
            print("Encrypted sum:", resp)
        elif c == "4":
            rid = input("Report ID: ").strip()
            resp = send_recv({"type":"AUDITOR_VERIFY_REPORT", "report_id": rid})
            print("Verify:", resp)
        elif c == "5":
            print(send_recv({"type":"LIST_RECORDS"}))
        else:
            break

def main():
    print("Choose role:")
    print("1) Doctor")
    print("2) Auditor")
    role = input("> ").strip()
    if role == "1":
        doctor_menu()
    else:
        auditor_menu()

if __name__ == "__main__":
    main()
