"""
CSA51 - Program 25: DSA Signature Randomization Analysis
Demonstrates DSA signing/verification and the danger of reusing k (nonce).
"""
import hashlib
import random

def is_prime(n):
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i+2) == 0: return False
        i += 6
    return True

def mod_inverse(a, m):
    def ext_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = ext_gcd(b % a, a)
        return g, y - (b // a) * x, x
    _, x, _ = ext_gcd(a % m, m)
    return x % m

def sha1_int(msg):
    h = hashlib.sha1(msg.encode()).digest()
    return int.from_bytes(h, 'big')

def dsa_sign(msg, p, q, g, x, k=None):
    if k is None:
        k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    if r == 0:
        return dsa_sign(msg, p, q, g, x)
    H = sha1_int(msg) % q
    k_inv = mod_inverse(k, q)
    s = (k_inv * (H + x * r)) % q
    if s == 0:
        return dsa_sign(msg, p, q, g, x)
    return r, s, k

def dsa_verify(msg, r, s, p, q, g, y):
    if not (0 < r < q and 0 < s < q):
        return False
    H = sha1_int(msg) % q
    w = mod_inverse(s, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r

def recover_private_key(msg1, msg2, r1, s1, r2, s2, q):
    """Recover x when k is reused (r1 == r2 implies same k)."""
    H1 = sha1_int(msg1) % q
    H2 = sha1_int(msg2) % q
    num = (H1 - H2) % q
    den = (s1 - s2) % q
    k = (num * mod_inverse(den, q)) % q
    k_inv = mod_inverse(k, q)
    x = (k_inv * (s1 * k - H1)) % q
    return k, x

def main():
    print("=" * 65)
    print("       DSA SIGNATURE RANDOMIZATION ANALYSIS")
    print("=" * 65)

    # Small DSA parameters for demonstration
    q = 23  # prime
    p = 47  # p = 2*q + 1 (safe prime)
    # Find g: generator of order q in Z*p
    g = 2
    while pow(g, q, p) != 1:
        g += 1

    x = random.randint(1, q - 1)  # private key
    y = pow(g, x, p)              # public key

    print(f"\nDSA Parameters (small demo values):")
    print(f"  p={p}, q={q}, g={g}")
    print(f"  Private x={x}")
    print(f"  Public  y={y}")

    print("\n--- Normal DSA Signing (random k) ---")
    msg1 = input("Enter message 1: ")
    r1, s1, k1 = dsa_sign(msg1, p, q, g, x)
    print(f"Signature(m1): r={r1}, s={s1}  [k={k1}]")
    print(f"Verify: {'✓ Valid' if dsa_verify(msg1, r1, s1, p, q, g, y) else '✗ Invalid'}")

    msg2 = input("Enter message 2: ")
    r2, s2, k2 = dsa_sign(msg2, p, q, g, x)
    print(f"Signature(m2): r={r2}, s={s2}  [k={k2}]")
    print(f"Verify: {'✓ Valid' if dsa_verify(msg2, r2, s2, p, q, g, y) else '✗ Invalid'}")

    print("\n--- Nonce Reuse Attack (k reused) ---")
    k_fixed = random.randint(1, q - 1)
    r1r, s1r, _ = dsa_sign(msg1, p, q, g, x, k=k_fixed)
    r2r, s2r, _ = dsa_sign(msg2, p, q, g, x, k=k_fixed)
    print(f"Sig(m1) with fixed k: r={r1r}, s={s1r}")
    print(f"Sig(m2) with fixed k: r={r2r}, s={s2r}")

    if r1r == r2r:
        k_rec, x_rec = recover_private_key(msg1, msg2, r1r, s1r, r2r, s2r, q)
        print(f"\nAttacker recovers k={k_rec}, private key x={x_rec}")
        print(f"Original x={x}")
        print(f"Attack {'SUCCEEDED' if x_rec == x else 'failed'}!")
    else:
        print(f"r1={r1r} != r2={r2r}: attack requires same r (same k).")

if __name__ == "__main__":
    main()
