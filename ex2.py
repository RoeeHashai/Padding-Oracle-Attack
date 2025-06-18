# ========================= STEP 1 ========================
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad,unpad

# ========================= STEP 2 ========================
plain_text = b"Hello World"
padded_text = pad(plain_text, DES.block_size)
print(padded_text)

# ========================= STEP 3 ========================
key = b"poaisfun"
iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(padded_text)
for byte in ciphertext:
    print(hex(byte))

# ========================= STEP 4 ========================
cipher = DES.new(key, DES.MODE_CBC, iv)
plain_text_padded = cipher.decrypt(ciphertext)
plain_text = unpad(plain_text_padded, DES.block_size)
print(plain_text)

# ========================= STEP 5 ========================
def xor(a, b, c):
    """
    input: a,b,c (int)
    output: a XOR b XOR c (bytes)
    """
    return bytes([a ^ b ^ c])

print(xor(0,0,0))
print(xor(0,0,1))
print(xor(0,1,0))
print(xor(0,1,1))
print(xor(1,0,0))
print(xor(1,0,1))
print(xor(1,1,0))
print(xor(1,1,1))

# ========================= STEP 6 ========================
def oracle(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    try:
        unpad(decrypted_text, DES.block_size)
        return True
    except ValueError:
        return False
    
print(oracle(ciphertext, key, iv))  # True
bad_ciphertext = DES.new(key, DES.MODE_CBC, iv).encrypt(b"0123456789abcde\x05")
print(oracle(bad_ciphertext, key, iv))  # False

# ========================= STEP 7 ========================
c = b'\x00' * 8 + ciphertext[8:]
for b in c:
    print(hex(b))

# ========================= STEP 8 ========================
c = bytearray(c)
for i in range(256):
    c[7] = i 
    if oracle(c, key, iv):
        print("Found valid ciphertext:", c.hex())
        break
    
# ========================= STEP 9 ========================
# P'_2[x] ^ C_i-1[x] ^ X_j[x]
P_2_7 = xor(1,ciphertext[7], c[7])      
print(P_2_7)
    
# ========================= STEP 10 ========================
# X_j[x] = P'_2[x] ^ C_i-1[x] ^ P_2[x]
X_j_7 = xor(2, ciphertext[7], P_2_7[0])[0] 
c[7] = X_j_7
print(c.hex())

# ========================= STEP 11 ========================
C1 = ciphertext[:8]
C2 = ciphertext[8:]
XJ = bytearray(8)               
XJ_C2 = XJ + bytearray(C2)      
plaintext = bytearray(8)

for byte_idx in reversed(range(8)):
    padding_val = 8 - byte_idx

    # Step 1: Brute-force byte at byte_idx in XJ
    for byte_val in range(256):
        XJ_C2[byte_idx] = byte_val
        if oracle(bytes(XJ_C2), key, iv):
            print(f"[+] Found valid byte {byte_idx}: {hex(byte_val)}")
            break

    # Step 2: Recover plaintext byte at byte_idx in P2
    plaintext[byte_idx] = xor(padding_val, C1[byte_idx], XJ_C2[byte_idx])[0]

    # Step 3: Update all known bytes to match new padding value
    next_pad = padding_val + 1
    for i in range(8 - byte_idx):
        pos = 7 - i
        XJ_C2[pos] = xor(next_pad, C1[pos], plaintext[pos])[0]

print("Recovered plaintext block:", bytes(plaintext))

# ========================= STEP 12 ========================
blocks_cnt = len(ciphertext) // DES.block_size
plaintext_blocks = []
for i in range(blocks_cnt):
    block_start = i * DES.block_size
    block_end = block_start + DES.block_size
    block_ciphertext = ciphertext[block_start:block_end]
    if i == 0:
        C_prev = iv
    else:
        C_prev = ciphertext[block_start - DES.block_size:block_start]
    XJ = bytearray(8)
    XJ_C2 = XJ + bytearray(block_ciphertext)
    plaintext_block = bytearray(8)
    for byte_idx in reversed(range(8)):
        padding_val = 8 - byte_idx

        # Step 1: Brute-force byte at byte_idx in XJ
        for byte_val in range(256):
            XJ_C2[byte_idx] = byte_val
            if oracle(bytes(XJ_C2), key, iv):
                print(f"[+] Found valid byte {byte_idx} in block {i}: {hex(byte_val)}")
                break

        # Step 2: Recover plaintext byte at byte_idx in P2
        plaintext_block[byte_idx] = xor(padding_val, C_prev[byte_idx], XJ_C2[byte_idx])[0]

        # Step 3: Update all known bytes to match new padding value
        next_pad = padding_val + 1
        for j in range(8 - byte_idx):
            pos = 7 - j
            XJ_C2[pos] = xor(next_pad, C_prev[pos], plaintext_block[pos])[0]
    plaintext_blocks.append(bytes(plaintext_block))

print("Full plaintext:", b''.join(plaintext_blocks))
    
# ========================= STEP 13 ========================
import sys
def padding_oracle_attack(ciphertext, key, iv):
    blocks_cnt = len(ciphertext) // DES.block_size
    plaintext_blocks = []
    for i in range(blocks_cnt):
        block_start = i * DES.block_size
        block_end = block_start + DES.block_size
        block_ciphertext = ciphertext[block_start:block_end]
        if i == 0:
            C_prev = iv
        else:
            C_prev = ciphertext[block_start - DES.block_size:block_start]
        XJ = bytearray(8)
        XJ_C2 = XJ + bytearray(block_ciphertext)
        plaintext_block = bytearray(8)
        for byte_idx in reversed(range(8)):
            padding_val = 8 - byte_idx

            # Step 1: Brute-force byte at byte_idx in XJ
            for byte_val in range(256):
                XJ_C2[byte_idx] = byte_val
                if oracle(bytes(XJ_C2), key, iv):
                    print(f"[+] Found valid byte {byte_idx} in block {i}: {hex(byte_val)}")
                    break

            # Step 2: Recover plaintext byte at byte_idx in P2
            plaintext_block[byte_idx] = xor(padding_val, C_prev[byte_idx], XJ_C2[byte_idx])[0]

            # Step 3: Update all known bytes to match new padding value
            next_pad = padding_val + 1
            for j in range(8 - byte_idx):
                pos = 7 - j
                XJ_C2[pos] = xor(next_pad, C_prev[pos], plaintext_block[pos])[0]
        plaintext_blocks.append(bytes(plaintext_block))
    return b''.join(plaintext_blocks)

def main():
    if len(sys.argv) != 4:
        print("Usage: python ex2.py <ciphertext> <key> <iv>")
        sys.exit(1)
    
    ciphertext = bytes.fromhex(sys.argv[1])
    key = bytes.fromhex(sys.argv[2])
    iv = bytes.fromhex(sys.argv[3])
    plaintext = padding_oracle_attack(ciphertext, key, iv)
    print("Recovered plaintext:", plaintext)
    print("Textual representation:", plaintext.decode('utf-8', errors='ignore'))
    
if __name__ == "__main__":
    main()