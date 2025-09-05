def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def initial_permutation(block):
    table = [58, 50, 42, 34, 26, 18, 10, 2,
             60, 52, 44, 36, 28, 20, 12, 4,
             62, 54, 46, 38, 30, 22, 14, 6,
             64, 56, 48, 40, 32, 24, 16, 8,
             57, 49, 41, 33, 25, 17,  9, 1,
             59, 51, 43, 35, 27, 19, 11, 3,
             61, 53, 45, 37, 29, 21, 13, 5,
             63, 55, 47, 39, 31, 23, 15, 7]
    return [block[i - 1] for i in table]

def final_permutation(block):
    reverse_table = [40, 8, 48, 16, 56, 24, 64, 32,
                     39, 7, 47, 15, 55, 23, 63, 31,
                     38, 6, 46, 14, 54, 22, 62, 30,
                     37, 5, 45, 13, 53, 21, 61, 29,
                     36, 4, 44, 12, 52, 20, 60, 28,
                     35, 3, 43, 11, 51, 19, 59, 27,
                     34, 2, 42, 10, 50, 18, 58, 26,
                     33, 1, 41,  9, 49, 17, 57, 25]
    return [block[i - 1] for i in reverse_table]

def expand_half_block(half_block):
    e_table = [32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9,10,11,12,13,
               12,13,14,15,16,17,
               16,17,18,19,20,21,
               20,21,22,23,24,25,
               24,25,26,27,28,29,
               28,29,30,31,32,1]
    return [half_block[i - 1] for i in e_table]

def substitute(s_input):
    s_output = []
    for i in range(0, 48, 6):
        chunk = s_input[i:i+6]
        folded = chunk[1:5]
        s_output.extend(folded)
    return s_output

def permutation_p(bits):
    return bits[4:] + bits[:4]

def feistel_round(left, right, round_key):
    expanded = expand_half_block(right)
    permuted = permutation_p(substitute(xor(expanded, round_key)))
    new_right = xor(left, permuted)
    return right, new_right

def generate_round_keys(key_64bit):
    keys = []
    for i in range(16):
        rotated = key_64bit[i:] + key_64bit[:i]
        round_key = rotated[:48]
        keys.append(round_key)
    return keys

def string_to_bitlist(s):
    bits = []
    for char in s:
        binval = bin(ord(char))[2:].rjust(8, '0')
        bits.extend([int(b) for b in binval])
    return bits

def pad_block(bitlist, length=64):
    if len(bitlist) > length:
        return bitlist[:length]
    while len(bitlist) < length:
        bitlist.append(0)
    return bitlist

def split_blocks(bitlist, block_size=64):
    blocks = []
    for i in range(0, len(bitlist), block_size):
        block = bitlist[i:i+block_size]
        blocks.append(pad_block(block, block_size))
    return blocks

def des_encrypt(plaintext_64bit, key_64bit):
    block = initial_permutation(plaintext_64bit)
    left = block[:32]
    right = block[32:]
    keys = generate_round_keys(key_64bit)
    for i in range(16):
        left, right = feistel_round(left, right, keys[i])
    combined = right + left
    ciphertext = final_permutation(combined)
    return ciphertext

def bitlist_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        byte_str = ''.join(str(b) for b in byte)
        chars.append(chr(int(byte_str, 2)))
    return ''.join(chars)

def des_decrypt(ciphertext_64bit, key_64bit):
    block = initial_permutation(ciphertext_64bit)
    left = block[:32]
    right = block[32:]
    keys = generate_round_keys(key_64bit)
    for i in range(15, -1, -1):
        left, right = feistel_round(left, right, keys[i])
    combined = right + left
    plaintext = final_permutation(combined)
    return plaintext

if __name__ == "__main__":
    pt = "Confidential Data"
    key = "A1B2C3D4"

    pt_bits = string_to_bitlist(pt)
    key_bits = pad_block(string_to_bitlist(key))

    pt_blocks = split_blocks(pt_bits)

    ciphertext_blocks = []
    for block in pt_blocks:
        ciphertext = des_encrypt(block, key_bits)
        ciphertext_blocks.append(ciphertext)

    print("Ciphertext blocks as string:")
    for cblock in ciphertext_blocks:
        print(bitlist_to_string(cblock))

    decrypted_bits = []
    for cblock in ciphertext_blocks:
        decrypted = des_decrypt(cblock, key_bits)
        decrypted_bits.extend(decrypted)

    print("Decrypted string:")
    print(bitlist_to_string(decrypted_bits).rstrip('\x00'))
