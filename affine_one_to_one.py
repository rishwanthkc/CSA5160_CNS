"""
CSA51 - Program 28: Affine Cipher One-to-One Property
Demonstrates and proves that affine cipher E(x)=(ax+b)mod 26 is one-to-one
(bijective) when gcd(a,26)=1, and many-to-one otherwise.
"""
from math import gcd

def affine_encrypt_char(x, a, b):
    return (a * x + b) % 26

def check_one_to_one(a, b):
    output = [affine_encrypt_char(x, a, b) for x in range(26)]
    return len(set(output)) == 26, output

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def main():
    print("=" * 65)
    print("       AFFINE CIPHER ONE-TO-ONE PROPERTY")
    print("=" * 65)
    print("E(x) = (a*x + b) mod 26")
    print("For the cipher to be bijective: gcd(a, 26) must equal 1\n")

    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
    invalid_a = [a for a in range(1, 26) if gcd(a, 26) != 1]

    print(f"Valid values of a   (coprime with 26): {valid_a}")
    print(f"Invalid values of a (not coprime)    : {invalid_a}")

    print("\n1. Test specific a and b values")
    print("2. Show full mapping for all valid a")
    print("3. Prove why invalid a breaks bijection")
    choice = input("Choice (1/2/3): ").strip()

    if choice == '1':
        a = int(input("Enter a: "))
        b = int(input("Enter b (0-25): "))
        is_bijective, outputs = check_one_to_one(a, b)
        print(f"\na={a}, b={b}, gcd(a,26)={gcd(a,26)}")
        print(f"Bijective: {'✓ YES' if is_bijective else '✗ NO'}")
        print("\nMapping (Plaintext → Ciphertext):")
        print(f"{'Plain':<8} {'Cipher':<8} {'Plain Char':<12} {'Cipher Char'}")
        print("-" * 45)
        for x, y in enumerate(outputs):
            pc = chr(x + ord('A'))
            cc = chr(y + ord('A'))
            print(f"{x:<8} {y:<8} {pc:<12} {cc}")
        if is_bijective:
            a_inv = mod_inverse(a, 26)
            print(f"\nDecryption: D(y) = {a_inv}*(y - {b}) mod 26")
        else:
            dups = [x for x in range(26) if outputs.count(outputs[x]) > 1]
            print(f"\nCollisions at inputs: {dups}")
            print("Multiple plaintexts map to same ciphertext → NOT decryptable!")

    elif choice == '2':
        b = int(input("Enter b (0-25): "))
        print(f"\nBijectivity check for all valid a values (b={b}):")
        print(f"{'a':<6} {'gcd(a,26)':<12} {'Bijective':<12} {'Unique outputs'}")
        print("-" * 45)
        for a in valid_a:
            bij, out = check_one_to_one(a, b)
            print(f"{a:<6} {gcd(a,26):<12} {'YES':<12} {len(set(out))}/26")

    elif choice == '3':
        print("\n--- Why Invalid 'a' Breaks Bijection ---")
        test_cases = [(2, 0), (4, 0), (6, 0), (13, 0)]
        for a, b in test_cases:
            _, out = check_one_to_one(a, b)
            unique = len(set(out))
            print(f"a={a:2}, gcd(a,26)={gcd(a,26)}: only {unique}/26 unique ciphertext values")
            if unique < 8:
                coll = {}
                for i, o in enumerate(out):
                    coll.setdefault(o, []).append(chr(i+ord('A')))
                print(f"   Collision example: {dict(list(coll.items())[:3])}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
