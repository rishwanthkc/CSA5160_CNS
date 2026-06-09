"""
CSA51 - Program 29: Hill Cipher Chosen-Plaintext Attack
Demonstrates how to recover the Hill cipher key matrix using chosen plaintext.
"""
import numpy as np
from math import gcd

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, mod):
    n = matrix.shape[0]
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = mod_inverse(det % mod, mod)
    if det_inv is None:
        raise ValueError(f"Matrix not invertible mod {mod}.")
    cofactors = np.zeros((n, n), dtype=int)
    for r in range(n):
        for c in range(n):
            minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
            cofactors[r][c] = ((-1)**(r+c)) * int(round(np.linalg.det(minor)))
    inv = (det_inv * cofactors.T) % mod
    return inv

def hill_encrypt_block(block, key):
    n = key.shape[0]
    v = np.array([ord(c) - ord('A') for c in block])
    return np.dot(key, v) % 26

def text_to_int(text):
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]

def int_to_text(ints):
    return ''.join(chr(i % 26 + ord('A')) for i in ints)

def attack(n, oracle_fn):
    """
    Chosen-plaintext attack for n×n Hill cipher.
    We choose n plaintexts whose matrix is invertible mod 26.
    """
    # Use identity-like plaintext blocks
    chosen_pts = []
    for i in range(n):
        block = ['A'] * n
        block[i] = chr(ord('A') + 1) if i == 0 else 'A'
        chosen_pts.append(''.join(block))

    # For 2x2, use AB, BA etc.
    if n == 2:
        chosen_pts = ['AB', 'BA']
    elif n == 3:
        chosen_pts = ['ABC', 'BCA', 'CAB']

    P_matrix = np.array([text_to_int(pt) for pt in chosen_pts]).T % 26
    print(f"\nChosen plaintexts: {chosen_pts}")
    print(f"Plaintext matrix P:\n{P_matrix}")

    # Get ciphertexts from oracle
    C_matrix = np.array([oracle_fn(pt) for pt in chosen_pts]).T % 26
    print(f"\nCorresponding ciphertexts: {[''.join(chr(x+ord('A')) for x in oracle_fn(pt)) for pt in chosen_pts]}")
    print(f"Ciphertext matrix C:\n{C_matrix}")

    # K = C * P^-1 mod 26
    try:
        P_inv = matrix_mod_inverse(P_matrix, 26)
        K_recovered = np.dot(C_matrix, P_inv) % 26
        return K_recovered.astype(int)
    except ValueError as e:
        print(f"Attack failed: {e}")
        return None

def main():
    print("=" * 65)
    print("     HILL CIPHER CHOSEN-PLAINTEXT ATTACK")
    print("=" * 65)

    n = int(input("Enter matrix size (2 or 3): "))
    print(f"\nEnter the {n}x{n} SECRET key matrix (attacker doesn't know this):")
    rows = []
    for i in range(n):
        row = list(map(int, input(f"Row {i+1}: ").split()))
        rows.append(row)
    K_secret = np.array(rows)
    print(f"Secret key:\n{K_secret}")

    def oracle(plaintext):
        text = ''.join(filter(str.isalpha, plaintext.upper()))[:n]
        return hill_encrypt_block(text, K_secret)

    print("\n--- Executing Chosen-Plaintext Attack ---")
    K_recovered = attack(n, oracle)

    if K_recovered is not None:
        print(f"\nRecovered Key Matrix:\n{K_recovered}")
        print(f"\nOriginal Key Matrix:\n{K_secret}")
        match = np.all(K_recovered == K_secret % 26)
        print(f"\nAttack {'SUCCEEDED' if match else 'FAILED'}")

        if match:
            verify_pt = input("\nVerify with plaintext: ")
            verify_pt = (verify_pt.upper() + 'X'*n)[:n]
            encrypted = hill_encrypt_block(verify_pt, K_secret)
            decrypted_parts = []
            K_inv = matrix_mod_inverse(K_recovered, 26)
            decrypted = np.dot(K_inv, encrypted) % 26
            print(f"Plaintext : {verify_pt}")
            print(f"Encrypted : {int_to_text(encrypted)}")
            print(f"Decrypted : {int_to_text(decrypted.astype(int))}")

if __name__ == "__main__":
    main()
