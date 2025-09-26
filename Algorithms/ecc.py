import random

# --- Helper Functions for ECC ---
def inverse_mod(k, p):
    """Modular inverse using Extended Euclidean Algorithm"""
    if k == 0:
        raise ZeroDivisionError("Division by zero in modular inverse")
    return pow(k, -1, p)

def is_on_curve(point, a, b, p):
    """Check if a point lies on the elliptic curve y^2 = x^3 + ax + b mod p"""
    if point is None:  # point at infinity
        return True
    x, y = point
    return (y * y - (x * x * x + a * x + b)) % p == 0

def point_add(point1, point2, a, p):
    """Add two points on the elliptic curve"""
    if point1 is None:
        return point2
    if point2 is None:
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        return None  # point at infinity

    if x1 == x2:
        # point doubling
        m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p)
    else:
        # point addition
        m = (y2 - y1) * inverse_mod(x2 - x1, p)

    m = m % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)

def scalar_mult(k, point, a, p):
    """Multiply a point by an integer k (repeated doubling/addition)"""
    result = None  # point at infinity
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1

    return result

# --- ECC Functions (similar style to RSA) ---
def ecc_keygen(a, b, p, G, n):
    """
    Generate ECC key pair
    :param a, b: curve parameters
    :param p: prime modulus
    :param G: base point (x, y)
    :param n: order of the base point
    :return: (private_key d, public_key Q)
    """
    d = random.randint(1, n-1)        # private key
    Q = scalar_mult(d, G, a, p)       # public key Q = d*G
    return d, Q

def ecc_encrypt(m, a, b, p, G, Q, n):
    """
    ECC Encryption (ElGamal style over ECC)
    :param m: plaintext message represented as a point on the curve
    :param a, b, p: curve parameters
    :param G: base point
    :param Q: recipient public key
    :param n: order of the base point
    :return: ciphertext (C1, C2)
    """
    k = random.randint(1, n-1)
    C1 = scalar_mult(k, G, a, p)
    kQ = scalar_mult(k, Q, a, p)
    C2 = point_add(m, kQ, a, p)
    return C1, C2

def ecc_decrypt(C1, C2, d, a, b, p):
    """
    ECC Decryption
    :param C1, C2: ciphertext points
    :param d: private key
    :param a, b, p: curve parameters
    :return: plaintext point m
    """
    dC1 = scalar_mult(d, C1, a, p)
    # m = C2 - d*C1
    neg_dC1 = (dC1[0], (-dC1[1]) % p)
    m = point_add(C2, neg_dC1, a, p)
    return m
