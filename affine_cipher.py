"""
CSA51 - Program 4: Affine Cipher
Encrypts using E(x) = (ax + b) mod 26 and decrypts using D(x) = a_inv*(x-b) mod 26.
"""
from math import gcd

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt(plaintext, a, b):
    if gcd(a, 26) != 1:
        raise ValueError(f"'a' ({a}) must be coprime with 26.")
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            enc = (a * x + b) % 26
            result.append(chr(enc + base))
        else:
            result.append(ch)
    return ''.join(result)

def affine_decrypt(ciphertext, a, b):
    if gcd(a, 26) != 1:
        raise ValueError(f"'a' ({a}) must be coprime with 26.")
    a_inv = mod_inverse(a, 26)
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - base
            dec = (a_inv * (y - b)) % 26
            result.append(chr(dec + base))
        else:
            result.append(ch)
    return ''.join(result)

def main():
    print("=" * 50)
    print("          AFFINE CIPHER")
    print("=" * 50)
    print("Valid values of 'a' (coprime with 26): 1,3,5,7,9,11,15,17,19,21,23,25")
    print("1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()

    text = input("Enter text: ")
    a = int(input("Enter key 'a' (must be coprime with 26): "))
    b = int(input("Enter key 'b' (shift, 0-25): ")) % 26

    try:
        if choice == '1':
            result = affine_encrypt(text, a, b)
            print(f"\nPlaintext : {text}")
            print(f"Keys      : a={a}, b={b}")
            print(f"Formula   : E(x) = ({a}x + {b}) mod 26")
            print(f"Ciphertext: {result}")
        elif choice == '2':
            a_inv = mod_inverse(a, 26)
            result = affine_decrypt(text, a, b)
            print(f"\nCiphertext: {text}")
            print(f"Keys       : a={a}, b={b}, a_inv={a_inv}")
            print(f"Formula    : D(y) = {a_inv}*(y - {b}) mod 26")
            print(f"Plaintext  : {result}")
        else:
            print("Invalid choice.")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
