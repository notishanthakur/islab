from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad

key=b"A1B2C3D4"
iv=b"12345678"
msg=b"Secure Communication"
cipher=DES.new(key,DES.MODE_CBC,iv)
ct=cipher.encrypt(pad(msg,8))
print("Ciphertext:",ct.hex())
pt=unpad(DES.new(key,DES.MODE_CBC,iv).decrypt(ct),8)
print("Decrypted:",pt.decode())
