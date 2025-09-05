from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD, inverse

key = ElGamal.generate(192, randfunc=get_random_bytes)

msg = b"Confidential Data"
m = int.from_bytes(msg, "big")

p = int(key.p)
g = int(key.g)
y = int(key.y)
x = int(key.x)

while True:
    k = random.StrongRandom().randint(1, p - 2)
    if GCD(k, p - 1) == 1:
        break

c1 = pow(g, k, p)
c2 = (m * pow(y, k, p)) % p

s = pow(c1, x, p)
s_inv = inverse(s, p)
decrypted_m = (c2 * s_inv) % p

decrypted_bytes = decrypted_m.to_bytes((decrypted_m.bit_length() + 7) // 8, "big")

print(f"c1 = {hex(c1)}")
print(f"c2 = {hex(c2)}")
print(f"Decrypted message: {decrypted_bytes.decode()}")
