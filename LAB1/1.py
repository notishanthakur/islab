from Crypto.Util.number import inverse

msg = "iamlearninginformationsecurity"
a,k=15,20
def to_nums(s): return [ord(c)-97 for c in s]
def to_str(n): return ''.join(chr(i+97) for i in n)

nums = to_nums(msg)

# Additive
add_enc = [(x+20)%26 for x in nums]
add_dec = [(x-20)%26 for x in add_enc]

# Multiplicative
mul_enc = [(x*15)%26 for x in nums]
mul_dec = [(x*inverse(15,26))%26 for x in mul_enc]

# Affine
aff_enc = [(a*x+k)%26 for x in nums]
aff_dec = [(inverse(a,26)*(x-k))%26 for x in aff_enc]

print("Additive:", to_str(add_enc), "->", to_str(add_dec))
print("Multiplicative:", to_str(mul_enc), "->", to_str(mul_dec))
print("Affine:", to_str(aff_enc), "->", to_str(aff_dec))