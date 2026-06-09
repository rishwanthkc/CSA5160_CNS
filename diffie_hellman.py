"""
CSA51 - Program 21: Diffie-Hellman Key Exchange Variant
Demonstrates the DH key exchange protocol step by step.
"""
import random

def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0: return False
    return True

def find_primitive_root(p):
    """Find a primitive root modulo p."""
    if p == 2: return 1
    phi = p - 1
    factors = set()
    n = phi
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    for g in range(2, p):
        if all(pow(g, phi // f, p) != 1 for f in factors):
            return g
    return None

def dh_exchange(p, g, a_private, b_private):
    A = pow(g, a_private, p)  # Alice's public
    B = pow(g, b_private, p)  # Bob's public
    shared_alice = pow(B, a_private, p)
    shared_bob   = pow(A, b_private, p)
    return A, B, shared_alice, shared_bob

def main():
    print("=" * 60)
    print("     DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 60)
    print("\n1. Manual input (small values for learning)")
    print("2. Auto-generate (random large prime)")
    mode = input("Choose mode (1/2): ").strip()

    if mode == '1':
        while True:
            p = int(input("Enter a prime p (public): "))
            if is_prime(p):
                break
            print(f"{p} is not prime. Try again.")
        g_suggest = find_primitive_root(p)
        print(f"Suggested primitive root g: {g_suggest}")
        g = int(input(f"Enter primitive root g (or press Enter to use {g_suggest}): ") or str(g_suggest))
        a = int(input("Enter Alice's private key a: "))
        b = int(input("Enter Bob's private key b: "))

    else:
        # Use a known safe prime for simplicity
        p = 2357  # A known prime
        while not is_prime(p):
            p = random.randint(1000, 9999)
        g = find_primitive_root(p)
        a = random.randint(2, p-2)
        b = random.randint(2, p-2)
        print(f"\nGenerated p = {p}")
        print(f"Primitive root g = {g}")
        print(f"Alice's private a = {a}")
        print(f"Bob's private b = {b}")

    A, B, shared_alice, shared_bob = dh_exchange(p, g, a, b)

    print(f"\n{'='*50}")
    print(f"Public Parameters:")
    print(f"  Prime p    = {p}")
    print(f"  Generator g = {g}")
    print(f"\nAlice:")
    print(f"  Private a       = {a}")
    print(f"  Public A = g^a mod p = {g}^{a} mod {p} = {A}")
    print(f"\nBob:")
    print(f"  Private b       = {b}")
    print(f"  Public B = g^b mod p = {g}^{b} mod {p} = {B}")
    print(f"\nShared Secret Computation:")
    print(f"  Alice: B^a mod p = {B}^{a} mod {p} = {shared_alice}")
    print(f"  Bob  : A^b mod p = {A}^{b} mod {p} = {shared_bob}")
    print(f"\nShared Secret Match: {'✓ YES - Secure Channel Established!' if shared_alice == shared_bob else '✗ NO - Error!'}")
    print(f"Shared Secret = {shared_alice}")

if __name__ == "__main__":
    main()
