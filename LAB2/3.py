from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b"0123456789ABCDEF0123456789ABCDEF"
msg = b"Encryption Strength"
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(msg, 16))
print("Ciphertext:", ct.hex())
pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
print("Decrypted:", pt.decode())
