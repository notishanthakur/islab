from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os,time

class KeyManager:
    def __init__(s):s.keys={}
    def gen_rsa(s,name):k=RSA.generate(2048);s.keys[name]=(k.publickey(),k);return k.publickey()
    def revoke(s,name):s.keys.pop(name,None)

km=KeyManager()
pubA=km.gen_rsa("Finance");pubB=km.gen_rsa("HR");pubC=km.gen_rsa("Supply")

msg=b"Financial Report"
c=PKCS1_OAEP.new(pubB).encrypt(msg)
m=PKCS1_OAEP.new(km.keys["HR"][1]).decrypt(c)

params=dh.generate_parameters(generator=2,key_size=512)
a=params.generate_private_key();b=params.generate_private_key()
sa=a.exchange(b.public_key());sb=b.exchange(a.public_key())
ka=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sa)
kb=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sb)

print(m.decode(),ka==kb)
