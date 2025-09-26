import random

def dh_keygen(p, g):
    """
    Diffie-Hellman Key Generation
    Params:
        p : int -> large prime modulus
        g : int -> generator of multiplicative group mod p
    Returns:
        private_key : int -> random secret exponent
        public_key : int -> g^private_key mod p
    """
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def dh_shared_secret(their_public, my_private, p):
    """
    Compute the shared secret
    Params:
        their_public : int -> other party's public key
        my_private : int -> my private key
        p : int -> prime modulus
    Returns:
        K : int -> shared secret
    """
    return pow(their_public, my_private, p)
