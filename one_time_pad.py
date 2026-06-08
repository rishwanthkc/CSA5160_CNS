"""
CSA51 - Program 9: One-Time Pad (Vigenere Variant)
Perfect secrecy cipher where key length equals message length.
"""
import random
import string

def generate_otp_key(length):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def otp_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    result = []
    k_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[k_idx]) - ord('A')
            enc = chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
            result.append(enc)
            k_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def otp_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    result = []
    k_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(key[k_idx]) - ord('A')
            dec = chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
            result.append(dec)
            k_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def alpha_count(text):
    return sum(1 for ch in text if ch.isalpha())

def main():
    print("=" * 55)
    print("         ONE-TIME PAD (VIGENERE VARIANT)")
    print("=" * 55)
    print("1. Encrypt (auto-generate OTP key)")
    print("2. Encrypt (provide your own key)")
    print("3. Decrypt")
    choice = input("Enter choice (1/2/3): ").strip()

    if choice in ('1', '2'):
        plaintext = input("Enter plaintext: ")
        n = alpha_count(plaintext)
        if choice == '1':
            key = generate_otp_key(n)
            print(f"\nAuto-generated OTP Key: {key}")
            print("(IMPORTANT: Save this key to decrypt later!)")
        else:
            key = input(f"Enter OTP key ({n} alphabetic chars): ").strip().upper()
            if alpha_count(key) < n:
                print(f"Key too short! Need at least {n} alphabetic characters.")
                return
        result = otp_encrypt(plaintext, key)
        print(f"\nPlaintext : {plaintext.upper()}")
        print(f"Key       : {key[:n]}")
        print(f"Ciphertext: {result}")

    elif choice == '3':
        ciphertext = input("Enter ciphertext: ")
        n = alpha_count(ciphertext)
        key = input(f"Enter OTP key ({n} alphabetic chars): ").strip().upper()
        if alpha_count(key) < n:
            print(f"Key too short! Need at least {n} alphabetic characters.")
            return
        result = otp_decrypt(ciphertext, key)
        print(f"\nCiphertext: {ciphertext.upper()}")
        print(f"Key        : {key[:n]}")
        print(f"Plaintext  : {result}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
