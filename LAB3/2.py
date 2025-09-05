from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
import os

priv=ec.generate_private_key(ec.SECP256R1())
pub=priv.public_key()
msg=b"Secure Transactions"
ep=ec.generate_private_key(ec.SECP256R1())
sh=ep.exchange(ec.ECDH(),pub)
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sh)
iv=os.urandom(16)
c=Cipher(algorithms.AES(key),modes.CFB(iv)).encryptor().update(msg)
sh2=priv.exchange(ec.ECDH(),ep.public_key())
key2=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sh2)
m=Cipher(algorithms.AES(key2),modes.CFB(iv)).decryptor().update(c)
print(c.hex()[:60]+"...",m.decode())
