"""
CSA51 - Program 6: Keyword-Based Substitution Cipher
Builds a substitution alphabet from a keyword, then uses it for encryption/decryption.
"""

def build_keyword_alphabet(keyword):
    keyword = keyword.upper()
    seen = []
    for ch in keyword:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    return ''.join(seen)

def encrypt(plaintext, cipher_alpha):
    plain_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    mapping = dict(zip(plain_alpha, cipher_alpha))
    result = []
    for ch in plaintext:
        if ch.isalpha():
            enc = mapping[ch.upper()]
            result.append(enc if ch.isupper() else enc.lower())
        else:
            result.append(ch)
    return ''.join(result)

def decrypt(ciphertext, cipher_alpha):
    plain_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    mapping = dict(zip(cipher_alpha, plain_alpha))
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            dec = mapping[ch.upper()]
            result.append(dec if ch.isupper() else dec.lower())
        else:
            result.append(ch)
    return ''.join(result)

def main():
    print("=" * 55)
    print("      KEYWORD-BASED SUBSTITUTION CIPHER")
    print("=" * 55)

    keyword = input("Enter keyword: ").strip()
    cipher_alpha = build_keyword_alphabet(keyword)

    print(f"\nKeyword          : {keyword.upper()}")
    print(f"Cipher Alphabet  : {cipher_alpha}")
    print(f"Plain Alphabet   : ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    print("\n1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()
    text = input("Enter text: ")

    if choice == '1':
        result = encrypt(text, cipher_alpha)
        print(f"\nPlaintext : {text}")
        print(f"Ciphertext: {result}")
    elif choice == '2':
        result = decrypt(text, cipher_alpha)
        print(f"\nCiphertext: {text}")
        print(f"Plaintext : {result}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
