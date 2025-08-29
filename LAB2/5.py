from Crypto.Cipher import AES

key=b"0123456789ABCDEF0123456789ABCDEF"
nonce=b"0000000000000000"
msg=b"Cryptography Lab Exercise"
cipher=AES.new(key,AES.MODE_CTR,nonce=nonce)
ct=cipher.encrypt(msg)
print("Ciphertext:",ct.hex())
pt=AES.new(key,AES.MODE_CTR,nonce=nonce).decrypt(ct)
print("Decrypted:",pt.decode())
