import hashlib

def derive_aes_key(shared_secret, key_len_bytes=16):
    """Derive AES key from DH shared secret"""
    return hashlib.sha256(str(shared_secret).encode()).digest()[:key_len_bytes]

aes_key = derive_aes_key(alice_shared)
print("Derived AES key (bytes):", aes_key)
