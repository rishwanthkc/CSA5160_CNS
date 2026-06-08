"""
CSA51 - Program 5: Simple Substitution Cipher Decryption
Encrypts/decrypts using a user-defined 26-letter substitution alphabet.
"""

def build_cipher_map(key_alphabet):
    plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypt_map = dict(zip(plain, key_alphabet.upper()))
    decrypt_map = dict(zip(key_alphabet.upper(), plain))
    return encrypt_map, decrypt_map

def substitute(text, mapping):
    result = []
    for ch in text:
        upper = ch.upper()
        if upper in mapping:
            enc = mapping[upper]
            result.append(enc if ch.isupper() else enc.lower())
        else:
            result.append(ch)
    return ''.join(result)

def main():
    print("=" * 55)
    print("       SIMPLE SUBSTITUTION CIPHER")
    print("=" * 55)
    print("Provide a 26-letter substitution alphabet (no repeats).")
    print("Example: QWERTYUIOPASDFGHJKLZXCVBNM")
    print()

    while True:
        key = input("Enter substitution alphabet (26 unique letters): ").strip().upper()
        if len(key) == 26 and len(set(key)) == 26 and key.isalpha():
            break
        print("Invalid! Must be exactly 26 unique alphabetic characters.")

    encrypt_map, decrypt_map = build_cipher_map(key)

    print("\nSubstitution Table:")
    plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    print("Plain :", ' '.join(plain))
    print("Cipher:", ' '.join(key))

    print("\n1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()
    text = input("Enter text: ")

    if choice == '1':
        result = substitute(text, encrypt_map)
        print(f"\nPlaintext : {text}")
        print(f"Ciphertext: {result}")
    elif choice == '2':
        result = substitute(text, decrypt_map)
        print(f"\nCiphertext: {text}")
        print(f"Plaintext : {result}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
