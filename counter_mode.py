"""
CSA51 - Program 17: Counter Mode (CTR) Encryption
Demonstrates AES-CTR mode encryption and decryption with nonce + counter.
"""
try:
    from Crypto.Cipher import AES
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.Cipher import AES
import os
import struct

BLOCK_SIZE = 16

def ctr_encrypt_manual(plaintext, key, nonce):
    """Manual CTR to show keystream generation."""
    blocks = [plaintext[i:i+BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]
    result = b''
    print(f"\n{'Block':<6} {'Counter':<20} {'Keystream Block':<35} {'Plaintext Block':<35} {'Ciphertext Block'}")
    print("-" * 130)
    for i, block in enumerate(blocks):
        counter_block = nonce + struct.pack('>Q', i)  # 8-byte nonce + 8-byte counter
        cipher = AES.new(key, AES.MODE_ECB)
        keystream = cipher.encrypt(counter_block)
        ct_block = bytes(x ^ y for x, y in zip(block, keystream[:len(block)]))
        result += ct_block
        print(f"{i+1:<6} {counter_block.hex():<20} {keystream.hex():<35} {block.hex():<35} {ct_block.hex()}")
    return result

def main():
    print("=" * 60)
    print("        COUNTER (CTR) MODE ENCRYPTION")
    print("=" * 60)

    print("1. Encrypt")
    print("2. Decrypt (same operation as encrypt in CTR)")
    choice = input("Enter choice (1/2): ").strip()

    text_hex = None
    if choice == '1':
        text = input("Enter plaintext: ").encode()
        key_opt = input("Auto-generate key? (y/n): ").strip().lower()
        if key_opt == 'y':
            key = os.urandom(16)
            print(f"Generated Key (hex): {key.hex()}")
        else:
            key = bytes.fromhex(input("Enter 32-char hex key: ").strip())

        nonce_opt = input("Auto-generate nonce? (y/n): ").strip().lower()
        if nonce_opt == 'y':
            nonce = os.urandom(8)
            print(f"Generated Nonce (hex): {nonce.hex()}")
        else:
            nonce = bytes.fromhex(input("Enter 16-char hex nonce (8 bytes): ").strip())

        print(f"\nPlaintext : {text.decode()}")
        print(f"Key       : {key.hex()}")
        print(f"Nonce     : {nonce.hex()}")
        print("\n--- Step-by-Step CTR Encryption ---")
        ciphertext = ctr_encrypt_manual(text, key, nonce)
        print(f"\nCiphertext (hex): {ciphertext.hex()}")
        print("\n(Save key and nonce to decrypt!)")

    elif choice == '2':
        ct_hex = input("Enter ciphertext (hex): ").strip()
        key_hex = input("Enter key (hex): ").strip()
        nonce_hex = input("Enter nonce (hex, 16 chars): ").strip()
        ct = bytes.fromhex(ct_hex)
        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        print("\n--- Step-by-Step CTR Decryption ---")
        plaintext = ctr_encrypt_manual(ct, key, nonce)
        print(f"\nPlaintext: {plaintext.decode(errors='replace')}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
