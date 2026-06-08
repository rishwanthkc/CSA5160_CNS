"""
CSA51 - Program 7: Playfair Cipher (Extended)
Extended version with detailed step-by-step encryption/decryption display.
"""

def generate_matrix(key):
    key = key.upper().replace('J', 'I')
    seen = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    return [seen[i*5:(i+1)*5] for i in range(5)]

def find_pos(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c

def prepare_pairs(text):
    text = text.upper().replace('J', 'I')
    text = ''.join(filter(str.isalpha, text))
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs

def process(matrix, pairs, mode):
    result = []
    d = 1 if mode == 'encrypt' else -1
    for a, b in pairs:
        r1, c1 = find_pos(matrix, a)
        r2, c2 = find_pos(matrix, b)
        if r1 == r2:
            na, nb = matrix[r1][(c1+d)%5], matrix[r2][(c2+d)%5]
            rule = "Same Row"
        elif c1 == c2:
            na, nb = matrix[(r1+d)%5][c1], matrix[(r2+d)%5][c2]
            rule = "Same Col"
        else:
            na, nb = matrix[r1][c2], matrix[r2][c1]
            rule = "Rectangle"
        result.append((a, b, na, nb, rule))
    return result

def main():
    print("=" * 60)
    print("      PLAYFAIR CIPHER (EXTENDED WITH STEPS)")
    print("=" * 60)

    key = input("Enter keyword: ")
    matrix = generate_matrix(key)

    print("\nPlayfair Matrix:")
    for row in matrix:
        print("  " + " ".join(row))

    print("\n1. Encrypt")
    print("2. Decrypt")
    choice = input("Enter choice (1/2): ").strip()
    text = input("Enter text: ")

    if choice == '1':
        pairs = prepare_pairs(text)
        steps = process(matrix, pairs, 'encrypt')
        print(f"\n{'Pair':<8} {'Result':<8} {'Rule'}")
        print("-" * 30)
        output = ""
        for a, b, na, nb, rule in steps:
            print(f"{a+b:<8} {na+nb:<8} {rule}")
            output += na + nb
        print(f"\nPlaintext : {text.upper()}")
        print(f"Ciphertext: {output}")

    elif choice == '2':
        text_clean = text.upper().replace('J','I')
        text_clean = ''.join(filter(str.isalpha, text_clean))
        pairs = [(text_clean[i], text_clean[i+1]) for i in range(0, len(text_clean), 2)]
        steps = process(matrix, pairs, 'decrypt')
        print(f"\n{'Pair':<8} {'Result':<8} {'Rule'}")
        print("-" * 30)
        output = ""
        for a, b, na, nb, rule in steps:
            print(f"{a+b:<8} {na+nb:<8} {rule}")
            output += na + nb
        print(f"\nCiphertext: {text.upper()}")
        print(f"Plaintext : {output}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
