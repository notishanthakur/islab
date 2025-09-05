from Crypto.Util.number import long_to_bytes

msg="thehouseisbeingsoldtonight".lower()
nums=[ord(c)-97 for c in msg]

def to_str(a): return ''.join(chr(i+97) for i in a)

# Vigenere
key="dollars"
k=[ord(c)-97 for c in key]
vig_enc=[(c+k[i%len(k)])%26 for i,c in enumerate(nums)]
vig_dec=[(vig_enc[i]-k[i%len(k)])%26 for i in range(len(vig_enc))]

# Autokey
k=[7]
auto_enc=[]
for i,c in enumerate(nums):
    keyv=k[i]
    e=(c+keyv)%26
    auto_enc.append(e)
    k.append(c)
auto_dec=[]
k=[7]
for i,c in enumerate(auto_enc):
    keyv=k[i]
    d=(c-keyv)%26
    auto_dec.append(d)
    k.append(d)

print("Vigenere:",to_str(vig_enc),"->",to_str(vig_dec))
print("Autokey:",to_str(auto_enc),"->",to_str(auto_dec))
