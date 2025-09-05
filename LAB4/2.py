from Crypto.Util import number
import time,os

class RabinKMS:
    def __init__(s):s.keys={};s.logs=[]
    def gen_key(s,name,bits=512):
        while True:
            p=number.getPrime(bits//2)
            if p%4==3:break
        while True:
            q=number.getPrime(bits//2)
            if q%4==3:break
        n=p*q;s.keys[name]={"pub":n,"priv":(p,q),"t":time.time()}
        s.logs.append(("gen",name,time.time()));return n,(p,q)
    def revoke(s,name):s.keys.pop(name,None);s.logs.append(("revoke",name,time.time()))
    def renew(s,name):return s.gen_key(name)
    def encrypt(s,m,n):return pow(m,2,n)
    def decrypt(s,c,p,q):
        mp=pow(c,(p+1)//4,p);mq=pow(c,(q+1)//4,q)
        yp, yq=number.inverse(p,q),number.inverse(q,p)
        r1=(yp*p*mq+yq*q*mp)% (p*q);r2=(p*q-r1);r3=(yp*p*mq-yq*q*mp)%(p*q);r4=(p*q-r3)
        return [r1,r2,r3,r4]

kms=RabinKMS()
pub,priv=kms.gen_key("Hospital1",512)
msg=12345
c=kms.encrypt(msg,pub)
d=kms.decrypt(c,*priv)
print(c,d)
