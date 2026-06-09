"""
CSA51 - Program 20: RSA Key Regeneration Security
Demonstrates why RSA keys must be regenerated securely and shows
the danger of reusing primes or using weak key generation.
"""
from math import gcd
import random

def is_prime(n, k=5):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime(n):
            return n

def mod_inverse(e, phi):
    def ext_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = ext_gcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = ext_gcd(e % phi, phi)
    return x % phi if g == 1 else None

def generate_rsa_keypair(bits=16):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
    d = mod_inverse(e, phi)
    return {'p': p, 'q': q, 'n': n, 'phi': phi, 'e': e, 'd': d}

def demonstrate_weak_key():
    print("\n--- Scenario 1: Reused Prime Attack ---")
    print("Two RSA keys share the same prime p (poor RNG).")
    p = generate_prime(12)
    q1 = generate_prime(12)
    q2 = generate_prime(12)
    while q1 == p: q1 = generate_prime(12)
    while q2 == p or q2 == q1: q2 = generate_prime(12)
    n1, n2 = p * q1, p * q2
    print(f"n1 = {n1}  (p={p}, q1={q1})")
    print(f"n2 = {n2}  (p={p}, q2={q2})")
    common = gcd(n1, n2)
    print(f"GCD(n1, n2) = {common}")
    if common > 1 and common != n1:
        print(f"VULNERABILITY: Shared factor p={common} found! Both keys are broken.")
    else:
        print("No common factor (safe).")

def demonstrate_small_e_attack():
    print("\n--- Scenario 2: Small e Broadcast Attack (e=3) ---")
    e = 3
    keys = []
    for _ in range(3):
        key = generate_rsa_keypair(16)
        key['e'] = e
        key['d'] = mod_inverse(e, key['phi'])
        keys.append(key)
    m = 42
    ciphertexts = [pow(m, e, k['n']) for k in keys]
    print(f"Same message m={m} encrypted with e=3 to 3 different keys:")
    for i, c in enumerate(ciphertexts):
        print(f"  c{i+1} = {c}  (n{i+1} = {keys[i]['n']})")
    # CRT recovery
    from functools import reduce
    def crt(residues, moduli):
        M = reduce(lambda a, b: a * b, moduli)
        result = 0
        for r, m in zip(residues, moduli):
            Mi = M // m
            result += r * Mi * mod_inverse(Mi, m)
        return result % M
    x = crt(ciphertexts, [k['n'] for k in keys])
    # Cube root
    recovered = round(x ** (1/3))
    print(f"\nCRT result x = m^3 = {x}")
    print(f"Cube root → recovered m = {recovered}")
    print(f"Attack {'SUCCEEDED' if recovered == m else 'failed (try larger range)'}!")

def main():
    print("=" * 65)
    print("         RSA KEY REGENERATION SECURITY")
    print("=" * 65)
    print("1. Generate a fresh RSA key pair")
    print("2. Demonstrate reused prime vulnerability")
    print("3. Demonstrate small-e broadcast attack")
    choice = input("Choice (1/2/3): ").strip()

    if choice == '1':
        bits = int(input("Enter prime bit size (e.g. 16, 32): ") or "16")
        key = generate_rsa_keypair(bits)
        print(f"\n--- Generated RSA Key Pair ---")
        print(f"p         = {key['p']}")
        print(f"q         = {key['q']}")
        print(f"n         = {key['n']}")
        print(f"φ(n)      = {key['phi']}")
        print(f"Public e  = {key['e']}")
        print(f"Private d = {key['d']}")
        msg = int(input(f"\nTest encrypt/decrypt with m (< {key['n']}): "))
        c = pow(msg, key['e'], key['n'])
        m = pow(c, key['d'], key['n'])
        print(f"Encrypted : {c}")
        print(f"Decrypted : {m}")
    elif choice == '2':
        demonstrate_weak_key()
    elif choice == '3':
        demonstrate_small_e_attack()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
