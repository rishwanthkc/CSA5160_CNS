"""
CSA51 - Program 16: CBC Mode Encryption and Decryption
Demonstrates AES-CBC encryption/decryption with detailed step-by-step output.
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

def xor_blocks(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def cbc_encrypt_manual(plaintext, key, iv):
    """Manual CBC encryption to show steps."""
    padded = pad(plaintext, BLOCK_SIZE)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    prev = iv
    cipherblocks = []
    print(f"\n{'Block':<6} {'Plaintext Block':<35} {'XOR with Prev/IV':<35} {'Cipher Block'}")
    print("-" * 115)
    for i, block in enumerate(blocks):
        xored = xor_blocks(block, prev)
        cipher = AES.new(key, AES.MODE_ECB)
        enc = cipher.encrypt(xored)
        cipherblocks.append(enc)
        print(f"{i+1:<6} {block.hex():<35} {xored.hex():<35} {enc.hex()}")
        prev = enc
    return b''.join(cipherblocks)

def cbc_decrypt_manual(ciphertext, key, iv):
    """Manual CBC decryption to show steps."""
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    prev = iv
    plainblocks = []
    print(f"\n{'Block':<6} {'Cipher Block':<35} {'AES Decrypt':<35} {'XOR Plain'}")
    print("-" * 115)
    for i, block in enumerate(blocks):
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(block)
        plain = xor_blocks(dec, prev)
        plainblocks.append(plain)
        print(f"{i+1:<6} {block.hex():<35} {dec.hex():<35} {plain.hex()}")
        prev = block
    try:
        return unpad(b''.join(plainblocks), BLOCK_SIZE)
    except Exception:
        return b''.join(plainblocks)

def main():
    print("=" * 60)
    print("      CBC MODE ENCRYPTION AND DECRYPTION")
    print("=" * 60)

    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()

    if choice == '1':
        plaintext = input("Enter plaintext: ").encode()

        print("\nKey Options:")
        print("  1. Auto-generate 16-byte AES key")
        print("  2. Enter key (32 hex chars = 16 bytes)")
        kc = input("Choice: ").strip()
        if kc == '1':
            key = os.urandom(16)
            print(f"Generated Key: {key.hex()}")
        else:
            key = bytes.fromhex(input("Enter 32-char hex key: ").strip())

        print("\nIV Options:")
        print("  1. Auto-generate IV")
        print("  2. Enter IV (32 hex chars = 16 bytes)")
        ic = input("Choice: ").strip()
        if ic == '1':
            iv = os.urandom(16)
            print(f"Generated IV : {iv.hex()}")
        else:
            iv = bytes.fromhex(input("Enter 32-char hex IV: ").strip())

        print(f"\nPlaintext : {plaintext.decode()}")
        print(f"Key       : {key.hex()}")
        print(f"IV        : {iv.hex()}")
        print("\n--- Step-by-Step CBC Encryption ---")
        ciphertext = cbc_encrypt_manual(plaintext, key, iv)
        print(f"\nFinal Ciphertext (hex): {ciphertext.hex()}")
        print("\n(Save key and IV to decrypt!)")

    elif choice == '2':
        ct_hex = input("Enter ciphertext (hex): ").strip()
        key_hex = input("Enter key (hex): ").strip()
        iv_hex  = input("Enter IV (hex): ").strip()
        ciphertext = bytes.fromhex(ct_hex)
        key = bytes.fromhex(key_hex)
        iv  = bytes.fromhex(iv_hex)
        print("\n--- Step-by-Step CBC Decryption ---")
        plaintext = cbc_decrypt_manual(ciphertext, key, iv)
        print(f"\nPlaintext: {plaintext.decode(errors='replace')}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
