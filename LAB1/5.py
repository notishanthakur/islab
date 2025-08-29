msg="xviewywi"
shift=(ord("c")-ord("y"))%26
plain="".join(chr((ord(c)-97-shift)%26+97) for c in msg)
print("Attack: Known-plaintext attack")
print("Plaintext:",plain)
