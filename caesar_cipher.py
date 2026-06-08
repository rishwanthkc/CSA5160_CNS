"""
CSA51 - Program 1: Caesar Cipher
Encrypts and decrypts text using the Caesar cipher technique.
"""

def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

def main():
    print("=" * 50)
    print("       CAESAR CIPHER")
    print("=" * 50)
    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()

    text = input("Enter text: ")
    shift = int(input("Enter shift key (0-25): ")) % 26

    if choice == '1':
        result = caesar_encrypt(text, shift)
        print(f"\nPlaintext : {text}")
        print(f"Shift     : {shift}")
        print(f"Ciphertext: {result}")
    elif choice == '2':
        result = caesar_decrypt(text, shift)
        print(f"\nCiphertext: {text}")
        print(f"Shift     : {shift}")
        print(f"Plaintext : {result}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
