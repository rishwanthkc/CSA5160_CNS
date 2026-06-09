"""
CSA51 - Program 30: Additive Cipher Automated Cryptanalysis
Fully automated cryptanalysis of additive cipher using IC and chi-squared.
"""
import string

ENGLISH_FREQ = {
    'A':8.17,'B':1.49,'C':2.78,'D':4.25,'E':12.70,'F':2.23,'G':2.02,
    'H':6.09,'I':6.97,'J':0.15,'K':0.77,'L':4.03,'M':2.41,'N':6.75,
    'O':7.51,'P':1.93,'Q':0.10,'R':5.99,'S':6.33,'T':9.06,'U':2.76,
    'V':0.98,'W':2.36,'X':0.15,'Y':1.97,'Z':0.07
}
ENGLISH_IC = 0.0667

def index_of_coincidence(text):
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2: return 0
    freq = {c: text.count(c) for c in string.ascii_uppercase}
    return sum(f * (f-1) for f in freq.values()) / (n * (n-1))

def chi_squared(text):
    text = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n == 0: return float('inf')
    score = 0
    for c in string.ascii_uppercase:
        observed = text.count(c) / n * 100
        expected = ENGLISH_FREQ[c]
        score += ((observed - expected) ** 2) / expected
    return score

def decrypt_additive(ciphertext, shift):
    result = []
    for c in ciphertext.upper():
        if c.isalpha():
            result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def automated_crack(ciphertext):
    results = []
    for shift in range(26):
        decrypted = decrypt_additive(ciphertext, shift)
        ic = index_of_coincidence(decrypted)
        chi = chi_squared(decrypted)
        results.append((shift, ic, chi, decrypted))
    return results

def main():
    print("=" * 65)
    print("    ADDITIVE CIPHER AUTOMATED CRYPTANALYSIS")
    print("=" * 65)
    print("The program will automatically determine the shift key.")
    print()

    print("1. Crack a ciphertext")
    print("2. Encrypt then auto-crack (demo)")
    choice = input("Choice (1/2): ").strip()

    if choice == '2':
        plaintext = input("Enter plaintext: ")
        shift = int(input("Enter shift (0-25): "))
        ciphertext = decrypt_additive(plaintext, -shift)
        print(f"\nEncrypted: {ciphertext}")
    elif choice == '1':
        ciphertext = input("Enter ciphertext: ").upper()
    else:
        print("Invalid choice.")
        return

    print(f"\nAnalyzing: '{ciphertext}'")
    print(f"Text IC: {index_of_coincidence(ciphertext):.4f} (English IC ≈ {ENGLISH_IC})")

    results = automated_crack(ciphertext)

    # Sort by chi-squared (lower = more English-like)
    results_chi = sorted(results, key=lambda x: x[2])

    print(f"\n{'='*65}")
    print(f"{'Rank':<6} {'Shift':<8} {'IC':<10} {'Chi²':<12} {'Decrypted (first 40 chars)'}")
    print("-" * 65)
    for rank, (shift, ic, chi, dec) in enumerate(results_chi[:5], 1):
        print(f"{rank:<6} {shift:<8} {ic:<10.4f} {chi:<12.2f} {dec[:40]}")

    best = results_chi[0]
    print(f"\n{'='*65}")
    print(f"BEST GUESS: Shift = {best[0]}")
    print(f"Chi² Score: {best[2]:.2f}")
    print(f"IC        : {best[1]:.4f}")
    print(f"Decrypted : {best[3]}")

if __name__ == "__main__":
    main()
