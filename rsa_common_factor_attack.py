"""
CSA51 - Program 19: RSA Common Factor Attack
Demonstrates attacking RSA when two moduli share a common prime factor.
"""
from math import gcd

def mod_inverse(e, phi):
    def ext_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = ext_gcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = ext_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("No modular inverse.")
    return x % phi

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def attack(n1, n2, e1, e2, c1, c2):
    print("\n--- RSA Common Factor Attack ---")
    p = gcd(n1, n2)
    if p == 1:
        print("GCD = 1. No common factor found. Attack fails.")
        return
    print(f"GCD(n1, n2) = {p}  ← Shared prime!")

    q1 = n1 // p
    q2 = n2 // p
    print(f"\nFor key 1: n1={n1}, p={p}, q1={q1}")
    print(f"For key 2: n2={n2}, p={p}, q2={q2}")

    phi1 = (p - 1) * (q1 - 1)
    phi2 = (p - 1) * (q2 - 1)
    d1 = mod_inverse(e1, phi1)
    d2 = mod_inverse(e2, phi2)

    print(f"\nRecovered d1 = {d1}")
    print(f"Recovered d2 = {d2}")

    m1 = rsa_decrypt(c1, d1, n1)
    m2 = rsa_decrypt(c2, d2, n2)
    print(f"\nDecrypted message 1: {m1}")
    print(f"Decrypted message 2: {m2}")
    return m1, m2

def main():
    print("=" * 65)
    print("           RSA COMMON FACTOR ATTACK")
    print("=" * 65)
    print("Scenario: Two RSA keys share a prime factor (poor RNG).")
    print()
    print("1. Use demo values (small primes)")
    print("2. Enter custom values")
    choice = input("Choice (1/2): ").strip()

    if choice == '1':
        # Shared prime p=61, q1=53, q2=71
        p, q1, q2 = 61, 53, 71
        n1, n2 = p*q1, p*q2
        phi1, phi2 = (p-1)*(q1-1), (p-1)*(q2-1)
        e1 = e2 = 17
        d1, d2 = mod_inverse(e1, phi1), mod_inverse(e2, phi2)
        m1_orig, m2_orig = 42, 99
        c1 = pow(m1_orig, e1, n1)
        c2 = pow(m2_orig, e2, n2)

        print(f"\nVictim 1: n={n1}, e={e1}, ciphertext c={c1} (encrypted m={m1_orig})")
        print(f"Victim 2: n={n2}, e={e2}, ciphertext c={c2} (encrypted m={m2_orig})")
        attack(n1, n2, e1, e2, c1, c2)

    elif choice == '2':
        n1 = int(input("Enter n1: "))
        n2 = int(input("Enter n2: "))
        e1 = int(input("Enter e1: "))
        e2 = int(input("Enter e2: "))
        c1 = int(input("Enter ciphertext c1: "))
        c2 = int(input("Enter ciphertext c2: "))
        attack(n1, n2, e1, e2, c1, c2)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
