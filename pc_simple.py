from Algorithms import aes, modularinverse, des

p,q,e,m=13,19,5,42
key_aes = b"000000000000000000000000000000FF"
key_des=b"A1B2C3D4"
n=p*q
phi=(p-1)*(q-1)

d=modularinverse(e, phi)
print("M: ", m)
print("N: ", n)
print("D: ", d)
print("Phi: ", phi)
print("Public key: (", n,",",e,")")
print("Private key: (", n,",",d,")")

ct=pow(m,e,n)
print("RSA encrypted: ", ct)
aes_ct, aes_pt = aes(str(ct).encode(),key_aes)
print("AES encrypted: ", aes_ct)
print("AES decrypted: ", aes_pt)

pt= pow(int(aes_pt),d,n)

print("RSA decrypted: ", pt)

