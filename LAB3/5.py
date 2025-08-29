from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time

p=dh.generate_parameters(generator=2,key_size=512)
t=time.time();a=p.generate_private_key();A=a.public_key();b=p.generate_private_key();B=b.public_key();gen=time.time()-t
t=time.time();sa=a.exchange(B);sb=b.exchange(A)
ka=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sa)
kb=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"").derive(sb);ex=time.time()-t
print("Equal:",ka==kb,"Keygen",gen,"Exchange",ex)
