from Algorithms import modularinverse

def rabin_encrypt(m, n):
    """
    Rabin Encryption
    Params:
        m : int -> plaintext (must be < n)
        n : int -> public key (product of primes p and q)
    Returns:
        c : int -> ciphertext
    """
    c = pow(m, 2, n)
    return c


def rabin_decrypt(c, p, q):
    """
    Rabin Decryption
    Params:
        c : int -> ciphertext
        p, q : int -> private keys (primes, p ≡ q ≡ 3 mod 4)
    Returns:
        (r1, r2, r3, r4) : tuple of int -> four possible plaintexts
    """
    n = p * q

    # Step 1: compute square roots modulo p and q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # Step 2: use Extended Euclidean Algorithm to solve yp*p + yq*q = 1
    # (same modularinverse technique as in RSA)
    def extended_gcd(a, b):
        if b == 0:
            return (1, 0, a)
        else:
            x1, y1, g = extended_gcd(b, a % b)
            return (y1, x1 - (a // b) * y1, g)

    yp, yq, _ = extended_gcd(p, q)

    # Step 3: combine solutions with CRT
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    return r1, r2, r3, r4
