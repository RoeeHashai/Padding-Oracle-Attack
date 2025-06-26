from Cryptodome.Cipher import DES
import sys
import subprocess

def xor(a, b, c):
    """
    input: a,b,c (int)
    output: a XOR b XOR c (bytes)
    """
    return bytes([a ^ b ^ c])

def call_oracle(ciphertext, iv):
    """
    Calls external oracle.py and returns True if padding is valid (oracle returns 1), else False
    """
    result = subprocess.run(
        [sys.executable, "oracle.py", ciphertext.hex(), iv.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )
    try:
        return result.stdout.strip() == b'1'
    except:
        return False

def padding_oracle_attack(ciphertext, iv):
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
        plaintext_block = bytearray(8)
        for byte_idx in reversed(range(8)):
            padding_val = 8 - byte_idx

            # Step 1: Brute-force byte at byte_idx in XJ
            for byte_val in range(256):
                XJ[byte_idx] = byte_val
                if call_oracle(block_ciphertext, XJ):
                    print(f"[+] Found valid byte {byte_idx} in block {i}: {hex(byte_val)}")
                    break

            # Step 2: Recover plaintext byte at byte_idx in P2
            plaintext_block[byte_idx] = xor(padding_val, C_prev[byte_idx], XJ[byte_idx])[0]

            # Step 3: Update all known bytes to match new padding value
            next_pad = padding_val + 1
            for j in range(8 - byte_idx):
                pos = 7 - j
                XJ[pos] = xor(next_pad, C_prev[pos], plaintext_block[pos])[0]
        plaintext_blocks.append(bytes(plaintext_block))
    return b''.join(plaintext_blocks)

def main():
    if len(sys.argv) != 3:
        sys.exit(1)
    
    ciphertext = bytes.fromhex(sys.argv[1])
    iv = bytes.fromhex(sys.argv[2])
    
    plaintext = padding_oracle_attack(ciphertext, iv)
    print(plaintext.decode('utf-8', errors='ignore'))
    
if __name__ == "__main__":
    main()
