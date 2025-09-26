import random
from Algorithms import modularinverse  # you already have this

def elgamal_keygen(p, g):
    """
    ElGamal Key Generation
    Params:
        p : int -> large prime modulus
        g : int -> generator of multiplicative group mod p
    Returns:
        public_key : tuple (p, g, y)
        private_key : int (x)
    """
    x = random.randint(2, p - 2)      # private key
    y = pow(g, x, p)                  # public key component
    return (p, g, y), x


def elgamal_encrypt(m, public_key):
    """
    ElGamal Encryption
    Params:
        m : int -> plaintext (must be < p)
        public_key : tuple (p, g, y)
    Returns:
        ciphertext : tuple (c1, c2)
    """
    p, g, y = public_key
    k = random.randint(2, p - 2)      # random session key

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    return (c1, c2)


def elgamal_decrypt(ciphertext, private_key, public_key):
    """
    ElGamal Decryption
    Params:
        ciphertext : tuple (c1, c2)
        private_key : int (x)
        public_key : tuple (p, g, y)
    Returns:
        m : int -> recovered plaintext
    """
    p, g, y = public_key
    c1, c2 = ciphertext

    s = pow(c1, private_key, p)
    s_inv = modularinverse(s, p)
    m = (c2 * s_inv) % p

    return m
