"""
CSA51 - Program 14: ECB vs CBC Error Propagation
Demonstrates how a single-bit flip in ciphertext affects decryption
differently in ECB mode vs CBC mode.
"""
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE = 16

def encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))

def decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except Exception:
        return cipher.decrypt(ciphertext)

def encrypt_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))

def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except Exception:
        return cipher.decrypt(ciphertext)

def flip_bit(data, byte_pos, bit_pos=0):
    ba = bytearray(data)
    ba[byte_pos] ^= (1 << bit_pos)
    return bytes(ba)

def safe_decode(b):
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)

def main():
    print("=" * 65)
    print("       ECB vs CBC ERROR PROPAGATION ANALYSIS")
    print("=" * 65)

    plaintext_str = input("Enter plaintext (at least 32 chars recommended): ")
    if len(plaintext_str) < 16:
        plaintext_str = plaintext_str.ljust(32, 'X')
    plaintext = plaintext_str.encode()

    key = os.urandom(16)
    iv  = os.urandom(16)

    print(f"\nKey (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")
    print(f"\nOriginal Plaintext: {plaintext_str}")

    # ECB
    ecb_ct = encrypt_ecb(plaintext, key)
    print(f"\n--- ECB Mode ---")
    print(f"Ciphertext (hex): {ecb_ct.hex()}")

    flip_byte = 5
    ecb_ct_flipped = flip_bit(ecb_ct, flip_byte)
    ecb_dec_flipped = decrypt_ecb(ecb_ct_flipped, key)
    ecb_dec_normal  = decrypt_ecb(ecb_ct, key)

    print(f"\nNormal Decryption  : {safe_decode(ecb_dec_normal[:len(plaintext)])}")
    print(f"After bit flip at byte {flip_byte}:")
    print(f"Flipped Decryption : {safe_decode(ecb_dec_flipped[:len(plaintext)])}")
    print("=> In ECB: only the block containing the flipped bit is corrupted.\n")

    # CBC
    cbc_ct = encrypt_cbc(plaintext, key, iv)
    print(f"--- CBC Mode ---")
    print(f"Ciphertext (hex): {cbc_ct.hex()}")

    cbc_ct_flipped = flip_bit(cbc_ct, flip_byte)
    cbc_dec_flipped = decrypt_cbc(cbc_ct_flipped, key, iv)
    cbc_dec_normal  = decrypt_cbc(cbc_ct, key, iv)

    print(f"\nNormal Decryption  : {safe_decode(cbc_dec_normal[:len(plaintext)])}")
    print(f"After bit flip at byte {flip_byte}:")
    print(f"Flipped Decryption : {safe_decode(cbc_dec_flipped[:len(plaintext)])}")
    print("=> In CBC: the current block is fully corrupted + next block has")
    print("   a predictable 1-bit flip at the same position.")

if __name__ == "__main__":
    main()
