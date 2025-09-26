# symmetric_all.py
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
import hashlib

# -------------------------------
# AES Helpers
# -------------------------------
def _pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]*pad_len)

def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# -------------------------------
# AES 128
# -------------------------------
def aes_128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    key = key[:16]  # enforce 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(_pad(plaintext, 16))

def aes_128_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    key = key[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    return _unpad(cipher.decrypt(ciphertext))

def aes_128_generate_key() -> bytes:
    return get_random_bytes(16)

# -------------------------------
# AES 256
# -------------------------------
def aes_256_encrypt(key: bytes, plaintext: bytes) -> bytes:
    key = key[:32]  # enforce 32 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(_pad(plaintext, 16))

def aes_256_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    key = key[:32]
    cipher = AES.new(key, AES.MODE_ECB)
    return _unpad(cipher.decrypt(ciphertext))

def aes_256_generate_key() -> bytes:
    return get_random_bytes(32)

# -------------------------------
# AES 512 (simulated)
# -------------------------------
def aes_512_encrypt(key: bytes, plaintext: bytes) -> bytes:
    # derive 64-byte key
    key_hash = hashlib.sha512(key).digest()
    k1 = key_hash[:32]
    k2 = key_hash[32:]
    # encrypt twice
    intermediate = aes_256_encrypt(k1, plaintext)
    return aes_256_encrypt(k2, intermediate)

def aes_512_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    key_hash = hashlib.sha512(key).digest()
    k1 = key_hash[:32]
    k2 = key_hash[32:]
    intermediate = aes_256_decrypt(k2, ciphertext)
    return aes_256_decrypt(k1, intermediate)

def aes_512_generate_key() -> bytes:
    return get_random_bytes(64)

# -------------------------------
# DES
# -------------------------------
def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    key = key[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(_pad(plaintext, 8))

def des_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    key = key[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    return _unpad(cipher.decrypt(ciphertext))

def des_generate_key() -> bytes:
    return get_random_bytes(8)

# -------------------------------
# Triple DES (3DES)
# -------------------------------
def triple_des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    # key must be 16 or 24 bytes
    key = DES3.adjust_key_parity(key[:24])
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(_pad(plaintext, 8))

def triple_des_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    key = DES3.adjust_key_parity(key[:24])
    cipher = DES3.new(key, DES3.MODE_ECB)
    return _unpad(cipher.decrypt(ciphertext))

def triple_des_generate_key() -> bytes:
    return DES3.adjust_key_parity(get_random_bytes(24))

# -------------------------------
# Demo usage
# -------------------------------
if __name__=="__main__":
    data = b"Hello Encryption World!"

    # AES-128
    k128 = aes_128_generate_key()
    ct128 = aes_128_encrypt(k128, data)
    pt128 = aes_128_decrypt(k128, ct128)
    print("AES-128:", pt128)

    # AES-256
    k256 = aes_256_generate_key()
    ct256 = aes_256_encrypt(k256, data)
    pt256 = aes_256_decrypt(k256, ct256)
    print("AES-256:", pt256)

    # AES-512 (simulated)
    k512 = aes_512_generate_key()
    ct512 = aes_512_encrypt(k512, data)
    pt512 = aes_512_decrypt(k512, ct512)
    print("AES-512 (sim):", pt512)

    # DES
    kdes = des_generate_key()
    ctdes = des_encrypt(kdes, data)
    ptdes = des_decrypt(kdes, ctdes)
    print("DES:", ptdes)

    # Triple DES
    k3des = triple_des_generate_key()
    ct3des = triple_des_encrypt(k3des, data)
    pt3des = triple_des_decrypt(k3des, ct3des)
    print("3DES:", pt3des)
