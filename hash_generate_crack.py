"""
CSA51 - Program 36: Generate and Crack Hashes
Demonstrates hash generation (MD5, SHA1, SHA256, SHA3) and dictionary/brute-force cracking.
"""
import hashlib
import itertools
import string
import time

HASH_FUNCTIONS = {
    'md5'     : hashlib.md5,
    'sha1'    : hashlib.sha1,
    'sha224'  : hashlib.sha224,
    'sha256'  : hashlib.sha256,
    'sha512'  : hashlib.sha512,
    'sha3_256': hashlib.sha3_256,
}

def generate_hash(text, algo='sha256'):
    fn = HASH_FUNCTIONS.get(algo.lower())
    if not fn:
        return None
    return fn(text.encode()).hexdigest()

def generate_all(text):
    print(f"\n{'Algorithm':<12} {'Hash'}")
    print("-" * 80)
    for algo, fn in HASH_FUNCTIONS.items():
        print(f"{algo:<12} {fn(text.encode()).hexdigest()}")

def dictionary_attack(target_hash, algo, wordlist):
    fn = HASH_FUNCTIONS.get(algo.lower())
    print(f"\nDictionary attack on {algo.upper()} hash: {target_hash}")
    start = time.time()
    for word in wordlist:
        word = word.strip()
        h = fn(word.encode()).hexdigest()
        if h == target_hash:
            elapsed = time.time() - start
            print(f"✓ CRACKED! Password: '{word}' (found in {elapsed:.3f}s)")
            return word
    print(f"✗ Not found in dictionary ({len(wordlist)} words tried).")
    return None

def brute_force_attack(target_hash, algo, charset, max_len=4):
    fn = HASH_FUNCTIONS.get(algo.lower())
    print(f"\nBrute-force attack on {algo.upper()} hash (max {max_len} chars)...")
    start = time.time()
    count = 0
    for length in range(1, max_len + 1):
        for candidate in itertools.product(charset, repeat=length):
            word = ''.join(candidate)
            h = fn(word.encode()).hexdigest()
            count += 1
            if h == target_hash:
                elapsed = time.time() - start
                print(f"✓ CRACKED! Password: '{word}' ({count} attempts in {elapsed:.3f}s)")
                return word
    print(f"✗ Not found after {count} attempts.")
    return None

def demonstrate_rainbow_weakness():
    """Show that same password → same hash (no salt)."""
    passwords = ['password', 'password', '123456', 'password']
    print("\n--- No-Salt Rainbow Table Vulnerability ---")
    print(f"{'Password':<15} {'MD5 Hash'}")
    print("-" * 55)
    for pw in passwords:
        h = hashlib.md5(pw.encode()).hexdigest()
        print(f"{pw:<15} {h}")
    print("\nNotice: Same passwords produce same hashes → Rainbow table attack possible!")

    print("\n--- With Salt (bcrypt-style) ---")
    import os
    print(f"{'Password':<15} {'Salt':<12} {'Salted SHA256'}")
    print("-" * 80)
    for pw in passwords:
        salt = os.urandom(8).hex()
        h = hashlib.sha256((pw + salt).encode()).hexdigest()
        print(f"{pw:<15} {salt:<12} {h[:32]}...")
    print("Each hash is unique even for same passwords → Rainbow tables fail!")

def main():
    print("=" * 65)
    print("        HASH GENERATION AND CRACKING")
    print("=" * 65)
    print("1. Generate hashes")
    print("2. Dictionary attack")
    print("3. Brute-force attack")
    print("4. Demonstrate salt importance")
    choice = input("Choice: ").strip()

    if choice == '1':
        text = input("Enter text to hash: ")
        generate_all(text)

    elif choice == '2':
        algo = input("Hash algorithm (md5/sha1/sha256): ").strip() or "md5"
        target = input(f"Enter target {algo.upper()} hash to crack: ").strip()
        print("Enter wordlist (one word per line, empty line to finish):")
        wordlist = []
        while True:
            w = input()
            if not w:
                break
            wordlist.append(w)
        # Add common passwords
        common = ['password','123456','admin','letmein','qwerty','abc123',
                  'monkey','dragon','master','sunshine','princess']
        wordlist = common + wordlist
        dictionary_attack(target, algo, wordlist)

    elif choice == '3':
        algo = input("Hash algorithm (md5/sha1/sha256): ").strip() or "md5"
        target = input(f"Enter target {algo.upper()} hash: ").strip()
        charset_choice = input("Charset: 1=digits, 2=lowercase, 3=alphanumeric: ").strip()
        if charset_choice == '1':
            charset = string.digits
        elif charset_choice == '2':
            charset = string.ascii_lowercase
        else:
            charset = string.ascii_lowercase + string.digits
        max_len = int(input("Max password length (1-5 recommended): ") or "4")
        brute_force_attack(target, algo, charset, max_len)

    elif choice == '4':
        demonstrate_rainbow_weakness()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
