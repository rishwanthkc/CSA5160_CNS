"""
CSA51 - Program 11: Monoalphabetic Cipher Frequency Attack
Breaks monoalphabetic substitution cipher using letter frequency analysis.
"""

ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

def frequency_analysis(text):
    text = text.upper()
    freq = {}
    total = sum(1 for c in text if c.isalpha())
    for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        count = text.count(ch)
        freq[ch] = (count, count / total * 100 if total > 0 else 0)
    return freq

def auto_crack(ciphertext):
    freq = frequency_analysis(ciphertext)
    sorted_cipher = sorted(freq.items(), key=lambda x: -x[1][0])
    cipher_order = [ch for ch, _ in sorted_cipher if freq[ch][0] > 0]
    mapping = {}
    for i, c_char in enumerate(cipher_order):
        if i < len(ENGLISH_ORDER):
            mapping[c_char] = ENGLISH_ORDER[i]
    return mapping

def apply_mapping(ciphertext, mapping):
    result = []
    for ch in ciphertext.upper():
        if ch.isalpha():
            result.append(mapping.get(ch, '?'))
        else:
            result.append(ch)
    return ''.join(result)

def main():
    print("=" * 60)
    print("   MONOALPHABETIC CIPHER FREQUENCY ATTACK")
    print("=" * 60)
    print("Provide a ciphertext. The longer it is, the better the analysis.")
    print()
    ciphertext = input("Enter ciphertext: ").strip()

    freq = frequency_analysis(ciphertext)
    print("\nLetter Frequency Analysis:")
    print(f"{'Letter':<8} {'Count':<8} {'Freq%':<10} {'Bar'}")
    print("-" * 50)
    for ch, (count, pct) in sorted(freq.items(), key=lambda x: -x[1][0]):
        if count > 0:
            bar = '█' * int(pct)
            print(f"{ch:<8} {count:<8} {pct:<10.2f} {bar}")

    mapping = auto_crack(ciphertext)
    print("\nAuto-derived Substitution Mapping (Cipher → Plain):")
    for c, p in sorted(mapping.items()):
        print(f"  {c} → {p}")

    decrypted = apply_mapping(ciphertext, mapping)
    print(f"\nAuto-Decrypted Text:\n{decrypted}")

    print("\n--- Manual Correction ---")
    print("Enter corrections as 'CIPHER_LETTER=PLAIN_LETTER' (e.g., X=T)")
    print("Type 'done' to finish.")
    while True:
        entry = input("Correction (or 'done'): ").strip().upper()
        if entry == 'DONE':
            break
        if '=' in entry:
            parts = entry.split('=')
            if len(parts) == 2 and len(parts[0]) == 1 and len(parts[1]) == 1:
                mapping[parts[0]] = parts[1]
                decrypted = apply_mapping(ciphertext, mapping)
                print(f"Updated: {decrypted}")
            else:
                print("Invalid format. Use: X=T")

    print(f"\nFinal Decrypted Text:\n{decrypted}")

if __name__ == "__main__":
    main()
