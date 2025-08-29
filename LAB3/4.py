import time,os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

data=os.urandom(1024*1024)

t=time.time();k=RSA.generate(2048);pub,priv=k.publickey(),k;gen_rsa=time.time()-t
t=time.time();c=PKCS1_OAEP.new(pub).encrypt(data[:200]);PKCS1_OAEP.new(priv).decrypt(c);rsa_time=time.time()-t

t=time.time();priv_ec=ec.generate_private_key(ec.SECP256R1());pub_ec=priv_ec.public_key();gen_ecc=time.time()-t
t=time.time();ep=ec.generate_private_key(ec.SECP256R1());sh=ep.exchange(ec.ECDH(),pub_ec)
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sh)
iv=os.urandom(16);c=Cipher(algorithms.AES(key),modes.CFB(iv)).encryptor().update(data)
sh2=priv_ec.exchange(ec.ECDH(),ep.public_key());key2=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sh2)
Cipher(algorithms.AES(key2),modes.CFB(iv)).decryptor().update(c);ecc_time=time.time()-t

print("RSA keygen",gen_rsa,"RSA enc/dec",rsa_time,"ECC keygen",gen_ecc,"ECC enc/dec",ecc_time)
