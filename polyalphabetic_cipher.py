"""
CSA51 - Program 3: Polyalphabetic Substitution Cipher (Vigenere Cipher)
Encrypts and decrypts using multiple Caesar ciphers based on a keyword.
"""

def vigenere_encrypt(plaintext, key):
    key = key.upper()
    result = []
    key_idx = 0
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = []
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)

def show_tableau(key, plaintext):
    print("\nEncryption Tableau (first 10 chars):")
    print(f"{'Plaintext':<12} {'Key Char':<10} {'Shift':<8} {'Ciphertext'}")
    print("-" * 45)
    key = key.upper()
    key_idx = 0
    count = 0
    for ch in plaintext:
        if ch.isalpha() and count < 10:
            shift = ord(key[key_idx % len(key)]) - ord('A')
            enc = chr((ord(ch.upper()) - ord('A') + shift) % 26 + ord('A'))
            print(f"{ch:<12} {key[key_idx % len(key)]:<10} {shift:<8} {enc}")
            key_idx += 1
            count += 1
        elif not ch.isalpha():
            continue

def main():
    print("=" * 50)
    print("   POLYALPHABETIC SUBSTITUTION (VIGENERE)")
    print("=" * 50)
    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()

    text = input("Enter text: ")
    key = input("Enter keyword: ")

    if not key.isalpha():
        print("Key must contain only alphabets.")
        return

    if choice == '1':
        result = vigenere_encrypt(text, key)
        show_tableau(key, text)
        print(f"\nPlaintext : {text}")
        print(f"Key       : {key}")
        print(f"Ciphertext: {result}")
    elif choice == '2':
        result = vigenere_decrypt(text, key)
        print(f"\nCiphertext: {text}")
        print(f"Key        : {key}")
        print(f"Plaintext  : {result}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
