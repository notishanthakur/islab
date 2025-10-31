#!/usr/bin/env python3
"""
Privacy-preserving Medical Records Server (template).
- TCP socket JSON messages
- Persistent JSON storage (db.json)
- Thread-safe file operations
- Replace crypto placeholders in designated CRYPTO SWAP AREA
"""

import socket, threading, json, os, time
from datetime import datetime
from pathlib import Path
from base64 import b64encode, b64decode
from threading import Lock

DB_PATH = Path("db.json")
HOST = "127.0.0.1"
PORT = 9000
lock = Lock()

# -------------------------
# DB helpers (thread-safe)
# -------------------------
def init_db():
    if not DB_PATH.exists():
        with DB_PATH.open("w") as f:
            json.dump({"doctors": {}, "reports": {}, "audits": []}, f, indent=2)

def read_db():
    with lock:
        with DB_PATH.open("r") as f:
            return json.load(f)

def write_db(data):
    with lock:
        with DB_PATH.open("w") as f:
            json.dump(data, f, indent=2)

# -------------------------
# CRYPTO SWAP AREA
# Replace these placeholders with real implementations
# Keep signatures / return types same so main server logic remains unchanged
# -------------------------
def generate_doctor_keys():
    """
    Client should normally generate keys. Server-side only stores public parts.
    Return format sample: {"rsa_pub": "...", "elgamal_pub": "...", "paillier_pub": "..."}
    """
    return {}  # server does not generate; placeholder

def paillier_encrypt_department_plaintext(dept_plaintext):
    """
    Input: dept_plaintext (string)
    Output: string-serializable representation of encrypted department (base64 or json)
    Replace with Paillier encryption of hashed keyword(s).
    """
    return b64encode(dept_plaintext.encode()).decode()

def paillier_keyword_match(encrypted_keyword_query, stored_encrypted_dept):
    """
    Should perform privacy-preserving test whether query matches stored department.
    For template we do base64 compare (i.e. plain).
    Replace with a secure Paillier-based test or SSE approach.
    """
    return encrypted_keyword_query == stored_encrypted_dept

def rsa_homomorphic_add(ciphertexts):
    """
    Input: list of ciphertext strings (as stored)
    Output: aggregated ciphertext string (same format)
    Replace with an RSA-based homomorphic summation scheme if required.
    """
    # Template: ciphertexts are plain ints in string; sum them
    total = sum(int(x) for x in ciphertexts)
    return str(total)

def elgamal_verify_signature(pub, message_bytes, signature_blob):
    """
    Return True/False
    Replace with actual ElGamal signature verification.
    """
    # Template: signature_blob is base64 of "SIGNED:<msg>"
    try:
        import base64
        sig = base64.b64decode(signature_blob.encode()).decode()
        return sig == "SIGNED:" + message_bytes.decode()
    except Exception:
        return False

def aes_decrypt_report(aes_key_b64, nonce_b64, tag_b64, ciphertext_b64):
    """
    Server may need to decrypt for admin or auditor if they hold symmetric key.
    For privacy-preserving auditor operations, auditor should NOT have AES key.
    Replace with AES-GCM decryption and return plaintext bytes.
    """
    # Template: we assume plaintext was base64-encoded
    try:
        return b64decode(ciphertext_b64.encode())
    except:
        return None

# -------------------------
# End CRYPTO SWAP AREA
# -------------------------

# Message helpers
def send_json(conn, obj):
    data = (json.dumps(obj) + "\n").encode()
    conn.sendall(data)

def recv_json(conn):
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if b"\n" in chunk:
            break
    try:
        return json.loads(data.decode().strip())
    except:
        return None

# Business logic
def handle_register(conn, msg):
    """
    msg fields:
      role: "doctor"
      doctor_id: str
      public_keys: { "rsa":..., "elgamal":..., "paillier":... }
      dept_encrypted: <value from client paillier_encrypt_department_plaintext>
    """
    db = read_db()
    docs = db["doctors"]
    did = msg["doctor_id"]
    if did in docs:
        send_json(conn, {"status":"error","msg":"doctor already registered"})
        return
    docs[did] = {
        "public_keys": msg.get("public_keys", {}),
        "dept_enc": msg.get("dept_encrypted"),
        "expenses": [],   # list of encrypted expense amounts
        "reports": []     # report ids
    }
    write_db(db)
    send_json(conn, {"status":"ok","msg":"registered"})

def handle_submit_report(conn, msg):
    """
    msg fields:
      doctor_id, report_id, aes_key_encrypted (RSA-encrypted AES key),
      aes_iv_nonce, aes_tag, report_ciphertext (AES-GCM ciphertext, base64),
      signature (ElGamal signature), timestamp, expense_encrypted (for homomorphic sum)
    """
    db = read_db()
    did = msg["doctor_id"]
    if did not in db["doctors"]:
        send_json(conn, {"status":"error","msg":"unknown doctor"})
        return
    rid = msg["report_id"]
    report_entry = {
        "report_id": rid,
        "doctor_id": did,
        "aes_key_enc": msg["aes_key_encrypted"],
        "nonce": msg["aes_iv_nonce"],
        "tag": msg["aes_tag"],
        "ciphertext": msg["report_ciphertext"],
        "signature": msg["signature"],
        "timestamp": msg["timestamp"],
        "expense_enc": msg.get("expense_encrypted")
    }
    db["reports"][rid] = report_entry
    db["doctors"][did]["reports"].append(rid)
    if msg.get("expense_encrypted") is not None:
        db["doctors"][did]["expenses"].append(msg["expense_encrypted"])
    write_db(db)
    send_json(conn, {"status":"ok","msg":"report stored"})

def handle_auditor_search_department(conn, msg):
    """Search doctors by encrypted department keyword provided by auditor"""
    db = read_db()
    query_enc = msg["dept_query_encrypted"]
    matches = []
    for did, doc in db["doctors"].items():
        if paillier_keyword_match(query_enc, doc.get("dept_enc")):
            matches.append(did)
    send_json(conn, {"status":"ok","matches": matches})

def handle_auditor_sum_expenses(conn, msg):
    """
    Sum expenses across doctors or per-doctor while staying encrypted.
    msg: {"mode":"all" or "per_doctor", "doctor_id": optional}
    """
    db = read_db()
    if msg["mode"] == "all":
        all_ciphertexts = []
        for did, doc in db["doctors"].items():
            all_ciphertexts.extend(doc.get("expenses", []))
        if not all_ciphertexts:
            send_json(conn, {"status":"ok","sum_enc": None})
            return
        agg = rsa_homomorphic_add(all_ciphertexts)
        send_json(conn, {"status":"ok","sum_enc": agg})
    elif msg["mode"] == "per_doctor":
        did = msg["doctor_id"]
        doc = db["doctors"].get(did)
        if not doc:
            send_json(conn, {"status":"error","msg":"doctor not found"})
            return
        agg = rsa_homomorphic_add(doc.get("expenses", [])) if doc.get("expenses") else None
        send_json(conn, {"status":"ok","sum_enc": agg})
    else:
        send_json(conn, {"status":"error","msg":"unknown mode"})

def handle_auditor_verify_report(conn, msg):
    """
    Verify report authenticity & timestamp using stored public key
    msg: {"report_id": "..."}
    """
    db = read_db()
    rid = msg["report_id"]
    rep = db["reports"].get(rid)
    if not rep:
        send_json(conn, {"status":"error","msg":"report not found"})
        return
    did = rep["doctor_id"]
    pub = db["doctors"][did]["public_keys"].get("elgamal")
    # verify signature over (ciphertext || timestamp)
    message = (rep["ciphertext"] + "|" + rep["timestamp"]).encode()
    ok = elgamal_verify_signature(pub, message, rep["signature"])
    send_json(conn, {"status":"ok", "verified": ok, "timestamp": rep["timestamp"]})

def handle_list_records(conn, msg):
    db = read_db()
    send_json(conn, {"status":"ok", "reports": list(db["reports"].keys()), "doctors": list(db["doctors"].keys())})

# Main per-client thread
def client_thread(conn, addr):
    try:
        while True:
            msg = recv_json(conn)
            if not msg:
                break
            typ = msg.get("type")
            if typ == "REGISTER":
                handle_register(conn, msg)
            elif typ == "SUBMIT_REPORT":
                handle_submit_report(conn, msg)
            elif typ == "AUDITOR_SEARCH_DEPT":
                handle_auditor_search_department(conn, msg)
            elif typ == "AUDITOR_SUM_EXPENSES":
                handle_auditor_sum_expenses(conn, msg)
            elif typ == "AUDITOR_VERIFY_REPORT":
                handle_auditor_verify_report(conn, msg)
            elif typ == "LIST_RECORDS":
                handle_list_records(conn, msg)
            else:
                send_json(conn, {"status":"error","msg":"unknown request"})
    except Exception as e:
        print("client thread error:", e)
    finally:
        conn.close()

def start_server():
    init_db()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"Server listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            print("Connection from", addr)
            t = threading.Thread(target=client_thread, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    start_server()
