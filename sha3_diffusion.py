"""
CSA51 - Program 22: SHA-3 State Diffusion Analysis
Analyzes the avalanche effect of SHA-3 (Keccak) hash function.
"""
import hashlib

def sha3_variants(text):
    enc = text.encode('utf-8')
    return {
        'SHA3-224': hashlib.sha3_224(enc).hexdigest(),
        'SHA3-256': hashlib.sha3_256(enc).hexdigest(),
        'SHA3-384': hashlib.sha3_384(enc).hexdigest(),
        'SHA3-512': hashlib.sha3_512(enc).hexdigest(),
    }

def bit_difference(hex1, hex2):
    b1 = bin(int(hex1, 16))[2:].zfill(len(hex1)*4)
    b2 = bin(int(hex2, 16))[2:].zfill(len(hex2)*4)
    diff = sum(a != b for a, b in zip(b1, b2))
    return diff, len(b1)

def flip_bit_in_text(text, pos):
    """Flip one bit in the UTF-8 encoding of text."""
    data = bytearray(text.encode('utf-8'))
    byte_pos = pos // 8
    bit_pos  = pos %  8
    if byte_pos < len(data):
        data[byte_pos] ^= (1 << bit_pos)
    return data.decode('utf-8', errors='replace')

def main():
    print("=" * 65)
    print("        SHA-3 STATE DIFFUSION ANALYSIS")
    print("=" * 65)

    text = input("Enter message: ")
    hashes = sha3_variants(text)

    print(f"\n--- SHA-3 Variants for: '{text}' ---")
    for algo, h in hashes.items():
        print(f"{algo:<12}: {h}")

    print("\n--- Avalanche Effect: Single Character Change ---")
    modified = text[:-1] + chr(ord(text[-1]) ^ 1) if text else "a"
    hashes2 = sha3_variants(modified)

    print(f"\nOriginal  : '{text}'")
    print(f"Modified  : '{modified}'")
    print(f"\n{'Algorithm':<12} {'Bit Diff':<12} {'Bit Total':<12} {'Diffusion %'}")
    print("-" * 55)
    for algo in hashes:
        diff, total = bit_difference(hashes[algo], hashes2[algo])
        pct = diff / total * 100
        print(f"{algo:<12} {diff:<12} {total:<12} {pct:.2f}%")

    print("\n--- Hash Comparison ---")
    print(f"\n{'Algorithm':<12} {'Original Hash':<70} {'Modified Hash'}")
    print("-" * 160)
    for algo in hashes:
        print(f"{algo:<12} {hashes[algo]:<70} {hashes2[algo]}")

    print("\n--- Bit-by-Bit Difference Visualization (SHA3-256) ---")
    h1 = bin(int(hashes['SHA3-256'], 16))[2:].zfill(256)
    h2 = bin(int(hashes2['SHA3-256'], 16))[2:].zfill(256)
    diff_str = ''.join('1' if a != b else '0' for a, b in zip(h1, h2))
    print("Diff bits (1=different): ")
    for i in range(0, 256, 64):
        print(f"  Bits {i:3}-{i+63:3}: {diff_str[i:i+64]}")
    print(f"\nTotal differing bits: {diff_str.count('1')}/256")

if __name__ == "__main__":
    main()
