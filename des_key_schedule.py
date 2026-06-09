"""
CSA51 - Program 12: DES Key Schedule Design
Demonstrates the DES key schedule: generating 16 subkeys from a 64-bit key.
"""

# Permuted Choice 1 (PC-1) - selects 56 bits from 64-bit key
PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]

# Permuted Choice 2 (PC-2) - selects 48 bits from 56-bit key
PC2 = [14,17,11,24,1,5,3,28,
       15,6,21,10,23,19,12,4,
       26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,
       51,45,33,48,44,49,39,56,
       34,53,46,42,50,36,29,32]

# Number of left shifts per round
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

def hex_to_bits(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(64)

def permute(bits, table):
    return ''.join(bits[i-1] for i in table)

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_subkeys(key_hex):
    key_bits = hex_to_bits(key_hex)
    print(f"\n64-bit Key (binary): {key_bits}")

    key56 = permute(key_bits, PC1)
    C, D = key56[:28], key56[28:]
    print(f"After PC-1 (56 bits): {key56}")

    subkeys = []
    print(f"\n{'Round':<8} {'C (28 bits)':<35} {'D (28 bits)':<35} {'Subkey (48 bits)'}")
    print("-" * 110)
    for i in range(16):
        C = left_shift(C, SHIFTS[i])
        D = left_shift(D, SHIFTS[i])
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)
        print(f"{i+1:<8} {C:<35} {D:<35} {subkey}")

    return subkeys

def main():
    print("=" * 60)
    print("         DES KEY SCHEDULE DESIGN")
    print("=" * 60)
    print("Enter a 64-bit DES key as 16 hexadecimal characters.")
    print("Example: 133457799BBCDFF1")
    key_hex = input("\nEnter 64-bit key (hex): ").strip().upper()

    if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
        print("Invalid key! Must be exactly 16 hex characters.")
        return

    subkeys = generate_subkeys(key_hex)
    print(f"\nAll 16 subkeys generated successfully.")
    print(f"\nSubkey Summary:")
    for i, sk in enumerate(subkeys):
        print(f"  K{i+1:02}: {sk}  (hex: {hex(int(sk,2))[2:].upper().zfill(12)})")

if __name__ == "__main__":
    main()
