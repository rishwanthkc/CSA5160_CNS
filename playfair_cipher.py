"""
CSA51 - Program 2: Playfair Cipher
Encrypts plaintext using the Playfair cipher with a keyword-based 5x5 matrix.
"""

def generate_matrix(key):
    key = key.upper().replace('J', 'I')
    seen = []
    for ch in key:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    matrix = [seen[i*5:(i+1)*5] for i in range(5)]
    return matrix

def find_position(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c
    return None

def prepare_text(text):
    text = text.upper().replace('J', 'I')
    text = ''.join(filter(str.isalpha, text))
    result = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i+1]
            if a == b:
                result.append(a)
                result.append('X')
                i += 1
            else:
                result.append(a)
                result.append(b)
                i += 2
        else:
            result.append(a)
            result.append('X')
            i += 1
    return result

def playfair_encrypt(matrix, text):
    pairs = prepare_text(text)
    ciphertext = []
    for i in range(0, len(pairs), 2):
        r1, c1 = find_position(matrix, pairs[i])
        r2, c2 = find_position(matrix, pairs[i+1])
        if r1 == r2:
            ciphertext += [matrix[r1][(c1+1)%5], matrix[r2][(c2+1)%5]]
        elif c1 == c2:
            ciphertext += [matrix[(r1+1)%5][c1], matrix[(r2+1)%5][c2]]
        else:
            ciphertext += [matrix[r1][c2], matrix[r2][c1]]
    return ''.join(ciphertext)

def playfair_decrypt(matrix, text):
    text = text.upper().replace('J', 'I')
    text = ''.join(filter(str.isalpha, text))
    plaintext = []
    for i in range(0, len(text), 2):
        r1, c1 = find_position(matrix, text[i])
        r2, c2 = find_position(matrix, text[i+1])
        if r1 == r2:
            plaintext += [matrix[r1][(c1-1)%5], matrix[r2][(c2-1)%5]]
        elif c1 == c2:
            plaintext += [matrix[(r1-1)%5][c1], matrix[(r2-1)%5][c2]]
        else:
            plaintext += [matrix[r1][c2], matrix[r2][c1]]
    return ''.join(plaintext)

def print_matrix(matrix):
    print("\nPlayfair Matrix:")
    for row in matrix:
        print(' '.join(row))

def main():
    print("=" * 50)
    print("       PLAYFAIR CIPHER")
    print("=" * 50)
    key = input("Enter keyword: ")
    matrix = generate_matrix(key)
    print_matrix(matrix)

    print("\n1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()
    text = input("Enter text: ")

    if choice == '1':
        result = playfair_encrypt(matrix, text)
        print(f"\nPlaintext : {text.upper()}")
        print(f"Ciphertext: {result}")
    elif choice == '2':
        result = playfair_decrypt(matrix, text)
        print(f"\nCiphertext: {text.upper()}")
        print(f"Plaintext : {result}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
