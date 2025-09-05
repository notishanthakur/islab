from Algorithms import modularinverse

def rsa_encrypt(p,q,e,plaintext):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modularinverse(e, phi)
    ciphertext = pow(plaintext, e, n)

    return d, n, ciphertext, phi
def rsa_decrypt(d, n, ciphertext):
    plaintext = pow(int(ciphertext), d, n)
    return plaintext
