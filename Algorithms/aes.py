from binascii import unhexlify

def aes(msg_aes,key_aes):
    def pkcs7_pad(b, bs):
        p = bs - (len(b) % bs or bs)
        return b + bytes([p]) * p

    def pkcs7_unpad(b):
        p = b[-1]
        return b[:-p]
    Sbox=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]
    InvS=[82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]
    Rcon=[0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

    def xor_bytes(a,b): return bytes(i^j for i,j in zip(a,b))
    def sub_bytes(s): return bytes(Sbox[b] for b in s)
    def inv_sub(s): return bytes(InvS[b] for b in s)

    def shift_rows(s):
        a=[list(s[i:i+4]) for i in range(0,16,4)]
        for r in range(1,4): a[r]=a[r][r:]+a[r][:r]
        return bytes(sum(a,[]))
    def inv_shift(s):
        a=[list(s[i:i+4]) for i in range(0,16,4)]
        for r in range(1,4): a[r]=a[r][-r:]+a[r][:-r]
        return bytes(sum(a,[]))

    def xtime(x): return ((x<<1)&0xff) ^ (0x1b if x&0x80 else 0)
    def mix_columns(s):
        s=list(s)
        for c in range(4):
            i=c
            a0,a1,a2,a3=s[i],s[i+4],s[i+8],s[i+12]
            t=a0^a1^a2^a3
            u=a0
            s[i]   ^= t ^ xtime(a0^a1)
            s[i+4] ^= t ^ xtime(a1^a2)
            s[i+8] ^= t ^ xtime(a2^a3)
            s[i+12]^= t ^ xtime(a3^u)
        return bytes(s)

    def mul(x,y):
        r=0
        for _ in range(8):
            if y&1: r^=x
            h=x&0x80
            x=(x<<1)&0xff
            if h: x^=0x1b
            y>>=1
        return r
    def inv_mix_columns(s):
        s=list(s)
        for c in range(4):
            i=c
            a0,a1,a2,a3=s[i],s[i+4],s[i+8],s[i+12]
            s[i]   = mul(a0,14)^mul(a1,11)^mul(a2,13)^mul(a3,9)
            s[i+4] = mul(a0,9)^mul(a1,14)^mul(a2,11)^mul(a3,13)
            s[i+8] = mul(a0,13)^mul(a1,9)^mul(a2,14)^mul(a3,11)
            s[i+12]= mul(a0,11)^mul(a1,13)^mul(a2,9)^mul(a3,14)
        return bytes(s)

    def add_round_key(s,k): return xor_bytes(s,k)

    def key_expansion(key16):
        w=[0]*176
        w[:16]=key16
        for i in range(16,176,4):
            t=w[i-4:i]
            if i%16==0:
                t=t[1:]+t[:1]
                t=[Sbox[b] for b in t]
                t[0]^=Rcon[i//16]
            for j in range(4):
                w[i+j]=w[i-16+j]^t[j]
        return [bytes(w[r:r+16]) for r in range(0,176,16)]

    def aes128_enc_block(b, rk):
        s=add_round_key(b,rk[0])
        for r in range(1,10):
            s=sub_bytes(s); s=shift_rows(s); s=mix_columns(s); s=add_round_key(s,rk[r])
        s=sub_bytes(s); s=shift_rows(s); s=add_round_key(s,rk[10])
        return s

    def aes128_dec_block(b, rk):
        s=add_round_key(b,rk[10])
        for r in range(9,0,-1):
            s=inv_shift(s); s=inv_sub(s); s=add_round_key(s,rk[r]); s=inv_mix_columns(s)
        s=inv_shift(s); s=inv_sub(s); s=add_round_key(s,rk[0])
        return s

    def aes_ecb_enc(pt, key_hex):
        key=unhexlify(key_hex)
        rk=key_expansion(list(key))
        pt=pkcs7_pad(pt,16)
        out=b''
        for i in range(0,len(pt),16):
            out+=aes128_enc_block(pt[i:i+16],rk)
        return out

    def aes_ecb_dec(ct, key_hex):
        key=unhexlify(key_hex)
        rk=key_expansion(list(key))
        out=b''
        for i in range(0,len(ct),16):
            out+=aes128_dec_block(ct[i:i+16],rk)
        return pkcs7_unpad(out)

    ct_aes=aes_ecb_enc(msg_aes,key_aes)
    pt_aes=aes_ecb_dec(ct_aes,key_aes)

    return ct_aes.hex(), pt_aes.decode()