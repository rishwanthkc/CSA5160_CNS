"""
CSA51 - Program 8: Hill Cipher Encryption and Decryption
Uses matrix multiplication for block encryption/decryption.
"""
import numpy as np
from math import gcd

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, mod):
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = mod_inverse(det % mod, mod)
    if det_inv is None:
        raise ValueError(f"Matrix is not invertible mod {mod}. det={det}")
    cofactors = np.zeros(matrix.shape, dtype=int)
    n = matrix.shape[0]
    for r in range(n):
        for c in range(n):
            minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
            cofactors[r][c] = ((-1)**(r+c)) * int(round(np.linalg.det(minor)))
    adjugate = cofactors.T % mod
    inv = (det_inv * adjugate) % mod
    return inv

def hill_encrypt(plaintext, key_matrix):
    n = key_matrix.shape[0]
    plaintext = plaintext.upper().replace(' ', '')
    plaintext = ''.join(filter(str.isalpha, plaintext))
    while len(plaintext) % n != 0:
        plaintext += 'X'

    result = []
    for i in range(0, len(plaintext), n):
        block = np.array([ord(c) - ord('A') for c in plaintext[i:i+n]])
        enc_block = np.dot(key_matrix, block) % 26
        result.extend([chr(int(x) + ord('A')) for x in enc_block])
    return ''.join(result)

def hill_decrypt(ciphertext, key_matrix):
    n = key_matrix.shape[0]
    ciphertext = ciphertext.upper().replace(' ', '')
    ciphertext = ''.join(filter(str.isalpha, ciphertext))
    inv_key = matrix_mod_inverse(key_matrix, 26)

    result = []
    for i in range(0, len(ciphertext), n):
        block = np.array([ord(c) - ord('A') for c in ciphertext[i:i+n]])
        dec_block = np.dot(inv_key, block) % 26
        result.extend([chr(int(round(x)) % 26 + ord('A')) for x in dec_block])
    return ''.join(result)

def input_matrix(n):
    print(f"Enter {n}x{n} key matrix row by row (space-separated integers):")
    rows = []
    for i in range(n):
        row = list(map(int, input(f"Row {i+1}: ").split()))
        rows.append(row)
    return np.array(rows)

def main():
    print("=" * 50)
    print("        HILL CIPHER")
    print("=" * 50)
    n = int(input("Enter matrix size (2 for 2x2, 3 for 3x3): "))
    key_matrix = input_matrix(n)
    print(f"\nKey Matrix:\n{key_matrix}")

    print("\n1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()
    text = input("Enter text: ")

    try:
        if choice == '1':
            result = hill_encrypt(text, key_matrix)
            print(f"\nPlaintext : {text.upper()}")
            print(f"Ciphertext: {result}")
        elif choice == '2':
            result = hill_decrypt(text, key_matrix)
            print(f"\nCiphertext: {text.upper()}")
            print(f"Plaintext : {result}")
        else:
            print("Invalid choice.")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
