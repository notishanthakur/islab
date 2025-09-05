from Algorithms import aes_128, rsa_encrypt, rsa_decrypt

p,q,e,m=13,19,5,42
key_aes = b"000000000000000000000000000000FF"
d,n,ct,phi=rsa_encrypt(p,q,e,m)
aes_ct, aes_pt = aes_128(str(ct).encode(),key_aes)

print("M: ", m)
print("N: ", n)
print("D: ", d)
print("Phi: ", phi)
print("Public key: (", n,",",e,")")
print("Private key: (", n,",",d,")")
print("RSA encrypted: ", ct)
print("AES encrypted: ", aes_ct)
print("AES decrypted: ", aes_pt)
print("RSA decrypted: ", rsa_decrypt(d,n,ct))
