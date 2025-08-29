from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key=RSA.generate(2048)
pub,priv=key.publickey(),key
msg=b"Asymmetric Encryption"
c=PKCS1_OAEP.new(pub).encrypt(msg)
m=PKCS1_OAEP.new(priv).decrypt(c)
print(c.hex()[:60]+"...",m.decode())
