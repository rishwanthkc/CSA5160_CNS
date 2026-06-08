"""
CSA51 - Program 10: Additive Cipher Frequency Attack
Breaks additive (Caesar) cipher using frequency analysis.
"""

ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}

def frequency_analysis(text):
    text = text.upper()
    freq = {}
    total = sum(1 for c in text if c.isalpha())
    for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        count = text.count(ch)
        freq[ch] = (count / total * 100) if total > 0 else 0
    return freq

def chi_squared(text_freq, shift):
    score = 0
    for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        shifted = chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
        observed = text_freq[ch]
        expected = ENGLISH_FREQ[shifted]
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score

def crack_additive(ciphertext):
    freq = frequency_analysis(ciphertext)
    scores = []
    for shift in range(26):
        score = chi_squared(freq, shift)
        decrypted = ''.join(
            chr((ord(c) - ord('A') - shift) % 26 + ord('A')) if c.isalpha() else c
            for c in ciphertext.upper()
        )
        scores.append((shift, score, decrypted))
    scores.sort(key=lambda x: x[1])
    return scores

def main():
    print("=" * 60)
    print("       ADDITIVE CIPHER FREQUENCY ATTACK")
    print("=" * 60)
    ciphertext = input("Enter ciphertext to crack: ")

    print("\nFrequency Analysis of Ciphertext:")
    freq = frequency_analysis(ciphertext)
    sorted_freq = sorted(freq.items(), key=lambda x: -x[1])
    for ch, f in sorted_freq[:10]:
        bar = '█' * int(f / 1)
        print(f"  {ch}: {f:5.2f}% {bar}")

    results = crack_additive(ciphertext)
    print("\nTop 5 Most Likely Decryptions (by Chi-Squared Score):")
    print(f"{'Rank':<6} {'Shift':<8} {'Chi²':<12} {'Decrypted Text (first 40 chars)'}")
    print("-" * 70)
    for i, (shift, score, text) in enumerate(results[:5]):
        print(f"{i+1:<6} {shift:<8} {score:<12.2f} {text[:40]}")

    print("\nBest guess:")
    best_shift, best_score, best_text = results[0]
    print(f"Shift     : {best_shift}")
    print(f"Chi² Score: {best_score:.2f}")
    print(f"Plaintext : {best_text}")

if __name__ == "__main__":
    main()
