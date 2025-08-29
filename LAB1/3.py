import string

msg="thekeyishiddenunderthedoorpad".replace("j","i")
key="guidance"
alpha="abcdefghiklmnopqrstuvwxyz"
matrix=[]
for c in key+alpha:
    if c not in matrix: matrix.append(c)
pairs=[]
i=0
while i<len(msg):
    a=msg[i]; b=msg[i+1] if i+1<len(msg) else 'x'
    if a==b: pairs.append((a,'x')); i+=1
    else: pairs.append((a,b)); i+=2
def pos(c): return divmod(matrix.index(c),5)
enc=[]
for a,b in pairs:
    ra,ca=pos(a); rb,cb=pos(b)
    if ra==rb: enc+=[matrix[ra*5+(ca+1)%5],matrix[rb*5+(cb+1)%5]]
    elif ca==cb: enc+=[matrix[((ra+1)%5)*5+ca],matrix[((rb+1)%5)*5+cb]]
    else: enc+=[matrix[ra*5+cb],matrix[rb*5+ca]]
print("Ciphertext:","".join(enc))
