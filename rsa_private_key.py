"""
CSA51 - Program 18: RSA Private Key Computation
Demonstrates RSA key generation, encryption, and decryption with full steps.
"""
from math import gcd
import random

def is_prime(n):
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i+2) == 0: return False
        i += 6
    return True

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Modular inverse doesn't exist.")
    return x % phi

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def get_prime(prompt):
    while True:
        val = int(input(prompt))
        if is_prime(val):
            return val
        print(f"{val} is not prime. Try again.")

def main():
    print("=" * 60)
    print("          RSA PRIVATE KEY COMPUTATION")
    print("=" * 60)
    print("RSA Steps: Choose p, q → n=p*q → φ(n)=(p-1)(q-1)")
    print("           Choose e: gcd(e,φ)=1 → d = e⁻¹ mod φ(n)")
    print()

    print("1. Manual RSA (enter small primes)")
    print("2. Auto RSA (random large primes)")
    mode = input("Choose mode (1/2): ").strip()

    if mode == '1':
        p = get_prime("Enter prime p: ")
        q = get_prime("Enter prime q (different from p): ")
        while q == p:
            q = get_prime("p and q must differ. Enter q: ")
    else:
        from sympy import nextprime, randprime
        bits = int(input("Enter bit size for primes (e.g. 512, 1024): ") or "64")
        lower = 2**(bits-1)
        upper = 2**bits
        p = randprime(lower, upper)
        q = randprime(lower, upper)
        while q == p:
            q = randprime(lower, upper)
        print(f"p = {p}")
        print(f"q = {q}")

    n = p * q
    phi = (p - 1) * (q - 1)
    print(f"\nn = p × q = {n}")
    print(f"φ(n) = (p-1)(q-1) = {phi}")

    print(f"\nChoose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1")
    while True:
        try:
            e = int(input("Enter e: "))
            if 1 < e < phi and gcd(e, phi) == 1:
                break
            print(f"Invalid e. gcd({e},{phi}) = {gcd(e,phi)}. Must be 1.")
        except ValueError:
            print("Enter a valid integer.")

    d = mod_inverse(e, phi)
    print(f"\n--- RSA Key Pair ---")
    print(f"Public Key  : (e={e}, n={n})")
    print(f"Private Key : (d={d}, n={n})")

    print("\n--- Encrypt/Decrypt ---")
    while True:
        try:
            msg = int(input(f"\nEnter integer message m (0 < m < {n}): "))
            if 0 < msg < n:
                break
            print(f"Message must be between 1 and {n-1}.")
        except ValueError:
            print("Enter a valid integer.")

    c = rsa_encrypt(msg, e, n)
    m_dec = rsa_decrypt(c, d, n)

    print(f"\nOriginal Message  : {msg}")
    print(f"Encrypted (c)     : {c}")
    print(f"Decrypted (m)     : {m_dec}")
    print(f"Match             : {'✓ YES' if m_dec == msg else '✗ NO'}")

if __name__ == "__main__":
    main()
