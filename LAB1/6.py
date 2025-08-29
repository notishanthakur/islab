from Crypto.Util.number import inverse

ct="XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS".lower()
pairs={'a':'g','b':'l'}
nums=lambda s:[ord(c)-97 for c in s]
to_str=lambda a:"".join(chr(i+97) for i in a)

for a in range(1,26,2):
    if a%13==0: continue
    for k in range(26):
        ok=True
        for p,c in pairs.items():
            if (a*(ord(p)-97)+k)%26!=(ord(c)-97): ok=False; break
        if ok:
            inv=inverse(a,26)
            dec=[(inv*((ord(c)-97)-k))%26 for c in ct]
            print("a=",a,"k=",k,"=>",to_str(dec))
