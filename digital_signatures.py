"""
CSA51 - Program 35: Verify Digital Signatures
Demonstrates RSA digital signature generation and verification.
"""
try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
import os

def generate_keys(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def sign(message, private_key):
    h = SHA256.new(message if isinstance(message, bytes) else message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature, h.hexdigest()

def verify(message, signature, public_key):
    h = SHA256.new(message if isinstance(message, bytes) else message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def save_keys(private_key, pub_key):
    with open("private.pem", "wb") as f:
        f.write(private_key.export_key())
    with open("public.pem", "wb") as f:
        f.write(pub_key.export_key())
    print("Keys saved to private.pem and public.pem")

def load_private_key():
    with open("private.pem", "rb") as f:
        return RSA.import_key(f.read())

def load_public_key():
    with open("public.pem", "rb") as f:
        return RSA.import_key(f.read())

def main():
    print("=" * 65)
    print("       DIGITAL SIGNATURE GENERATION & VERIFICATION")
    print("=" * 65)

    print("\n1. Generate key pair and sign a message")
    print("2. Verify a signature")
    print("3. Demonstrate tamper detection")
    print("4. Full demo (generate + sign + verify + tamper)")
    choice = input("Choice: ").strip()

    if choice == '1':
        bits = int(input("Key size in bits (1024/2048): ") or "2048")
        print(f"Generating {bits}-bit RSA key pair...")
        priv, pub = generate_keys(bits)
        save_keys(priv, pub)
        print(f"Public Key (n):\n{pub.n}")
        print(f"Public exponent e: {pub.e}")

        msg = input("\nEnter message to sign: ")
        sig, hash_val = sign(msg, priv)
        print(f"\nMessage         : {msg}")
        print(f"SHA-256 Hash    : {hash_val}")
        print(f"Signature (hex) : {sig.hex()[:64]}...")
        with open("signature.bin", "wb") as f:
            f.write(sig)
        with open("message.txt", "w") as f:
            f.write(msg)
        print("Signature saved to signature.bin, message to message.txt")

    elif choice == '2':
        msg_file = input("Message file (default: message.txt): ").strip() or "message.txt"
        sig_file = input("Signature file (default: signature.bin): ").strip() or "signature.bin"
        with open(msg_file, "r") as f:
            msg = f.read()
        with open(sig_file, "rb") as f:
            sig = f.read()
        pub = load_public_key()
        result = verify(msg, sig, pub)
        print(f"\nMessage   : {msg}")
        print(f"Signature : {sig.hex()[:32]}...")
        print(f"Result    : {'✓ VALID Signature' if result else '✗ INVALID Signature'}")

    elif choice == '3':
        msg = input("Enter original message: ")
        priv, pub = generate_keys(1024)
        sig, _ = sign(msg, priv)
        print(f"\nOriginal: '{msg}'")
        print(f"Verify original: {'✓ VALID' if verify(msg, sig, pub) else '✗ INVALID'}")

        tampered = msg + " (tampered)"
        print(f"Tampered: '{tampered}'")
        print(f"Verify tampered: {'✓ VALID' if verify(tampered, sig, pub) else '✗ INVALID - Tamper Detected!'}")

        sig_tampered = bytearray(sig)
        sig_tampered[0] ^= 0xFF
        print(f"\nVerify with modified signature: {'✓ VALID' if verify(msg, bytes(sig_tampered), pub) else '✗ INVALID - Signature Tampered!'}")

    elif choice == '4':
        print("\n--- Full Digital Signature Demo ---")
        priv, pub = generate_keys(1024)
        msg = input("Enter message: ")
        sig, hash_val = sign(msg, priv)
        print(f"\nSHA-256 Hash   : {hash_val}")
        print(f"Signature (hex): {sig.hex()[:48]}...")
        valid = verify(msg, sig, pub)
        print(f"\nVerification   : {'✓ VALID' if valid else '✗ INVALID'}")
        tampered = msg + "!"
        valid2 = verify(tampered, sig, pub)
        print(f"Tampered verify: {'✓ VALID' if valid2 else '✗ INVALID (tamper detected)'}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
