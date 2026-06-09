"""
CSA51 - Program 13: Triple DES in CBC Mode
Demonstrates 3DES-CBC encryption and decryption using Python's cryptography library.
"""
try:
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad, unpad
    import binascii, os
    PYCRYPTO = True
except ImportError:
    PYCRYPTO = False

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def manual_3des_demo(plaintext_bytes, key24, iv):
    """Simplified 3DES-CBC demo (illustrative, not actual DES)"""
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad, unpad
    cipher = DES3.new(key24, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext_bytes, 8))
    cipher2 = DES3.new(key24, DES3.MODE_CBC, iv)
    pt = unpad(cipher2.decrypt(ct), 8)
    return ct, pt

def main():
    print("=" * 60)
    print("       TRIPLE DES (3DES) IN CBC MODE")
    print("=" * 60)

    if not PYCRYPTO:
        print("Installing pycryptodome...")
        import subprocess
        subprocess.run(["pip", "install", "pycryptodome", "--break-system-packages", "-q"])
        from Crypto.Cipher import DES3
        from Crypto.Util.Padding import pad, unpad

    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad, unpad

    print("\n1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()

    if choice == '1':
        plaintext = input("Enter plaintext: ").encode()
        print("\nKey Options:")
        print("  1. Auto-generate 24-byte (192-bit) key")
        print("  2. Enter key manually (24 hex bytes = 48 hex chars)")
        kc = input("Choice: ").strip()
        if kc == '1':
            key = DES3.adjust_key_parity(os.urandom(24))
            print(f"Generated Key (hex): {key.hex()}")
        else:
            key_hex = input("Enter 48-char hex key: ").strip()
            key = bytes.fromhex(key_hex)
            key = DES3.adjust_key_parity(key)

        print("\nIV Options:")
        print("  1. Auto-generate IV")
        print("  2. Enter IV manually (8 hex bytes = 16 hex chars)")
        ic = input("Choice: ").strip()
        if ic == '1':
            iv = os.urandom(8)
            print(f"Generated IV (hex): {iv.hex()}")
        else:
            iv = bytes.fromhex(input("Enter 16-char hex IV: ").strip())

        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, 8))

        print(f"\nPlaintext   : {plaintext.decode()}")
        print(f"Key (hex)   : {key.hex()}")
        print(f"IV  (hex)   : {iv.hex()}")
        print(f"Ciphertext  : {ciphertext.hex()}")
        print(f"\n(Save the key and IV to decrypt later!)")

    elif choice == '2':
        ct_hex = input("Enter ciphertext (hex): ").strip()
        key_hex = input("Enter key (hex): ").strip()
        iv_hex = input("Enter IV (hex): ").strip()

        ciphertext = bytes.fromhex(ct_hex)
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)

        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 8)

        print(f"\nCiphertext  : {ct_hex}")
        print(f"Plaintext   : {plaintext.decode()}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
