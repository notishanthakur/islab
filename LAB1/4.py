import numpy as np

msg="weliveinaninsecureworld".lower().replace(" ","")
if len(msg)%2: msg+="x"
nums=[ord(c)-97 for c in msg]
K=np.array([[3,3],[2,7]])
enc=[]
for i in range(0,len(nums),2):
    v=np.array(nums[i:i+2])
    e=K.dot(v)%26
    enc+=list(e)
print("Ciphertext:","".join(chr(x+97) for x in enc))
