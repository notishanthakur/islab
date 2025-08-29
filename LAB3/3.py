from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto.Util.number import GCD

key=ElGamal.generate(256,random.getrandbits)
msg=b"Confidential Data"
m=int.from_bytes(msg,"big")
while True:
    k=random.StrongRandom().randint(1,key.p-2)
    if GCD(k,key.p-1)==1:break
c1,c2=key.encrypt(m,k)
d=key.decrypt((c1,c2))
print(hex(c1),hex(c2)[:20]+"...",d.to_bytes((d.bit_length()+7)//8,"big").decode())
