import hashlib
from Algorithms import aes_128  # your AES implementation

def derive_aes_key(shared_secret, key_size=16):
    """
    Derive an AES key from the shared secret using SHA-256
    Params:
        shared_secret : int
        key_size : int -> AES key length in bytes (16, 24, 32)
    Returns:
        key : bytes -> derived AES key
    """
    secret_bytes = str(shared_secret).encode()
    hashed = hashlib.sha256(secret_bytes).digest()
    return hashed[:key_size]


# Example: Student <-> Teacher key exchange
p = 467
g = 2

# Student side
student_priv, A = dh_keygen(p, g)

# Teacher side
teacher_priv, B = dh_keygen(p, g)

# Exchange A and B, compute shared secret
student_secret = dh_shared_secret(B, student_priv, p)
teacher_secret = dh_shared_secret(A, teacher_priv, p)

# Derive AES keys
student_aes_key = derive_aes_key(student_secret)
teacher_aes_key = derive_aes_key(teacher_secret)

print("AES keys match?", student_aes_key == teacher_aes_key)
