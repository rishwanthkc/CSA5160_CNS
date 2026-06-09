"""
CSA51 - Program 38: Encrypt and Sign Emails (PGP-style)
Simulates PGP email encryption and signing using RSA + AES.
"""
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
import os, base64, json

def generate_keypair(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def aes_encrypt(data, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, 16))

def aes_decrypt(data, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), 16)

def rsa_encrypt_key(aes_key, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(aes_key)

def rsa_decrypt_key(enc_key, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(enc_key)

def sign_message(data, priv_key):
    h = SHA256.new(data)
    return pkcs1_15.new(priv_key).sign(h)

def verify_signature(data, sig, pub_key):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, sig)
        return True
    except Exception:
        return False

def encrypt_email(subject, body, sender_priv, recipient_pub):
    """PGP-style email encryption + signing."""
    email_data = f"Subject: {subject}\n\n{body}".encode()

    # Sign with sender's private key
    signature = sign_message(email_data, sender_priv)

    # Generate session key
    aes_key = os.urandom(16)
    iv = os.urandom(16)

    # Encrypt body with AES
    encrypted_body = aes_encrypt(email_data, aes_key, iv)

    # Encrypt AES key with recipient's public key
    encrypted_key = rsa_encrypt_key(aes_key, recipient_pub)

    envelope = {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'encrypted_body': base64.b64encode(encrypted_body).decode(),
        'signature': base64.b64encode(signature).decode(),
    }
    return json.dumps(envelope)

def decrypt_email(envelope_json, recipient_priv, sender_pub):
    """Decrypt and verify PGP-style email."""
    env = json.loads(envelope_json)
    enc_key = base64.b64decode(env['encrypted_key'])
    iv = base64.b64decode(env['iv'])
    enc_body = base64.b64decode(env['encrypted_body'])
    sig = base64.b64decode(env['signature'])

    # Decrypt AES key
    aes_key = rsa_decrypt_key(enc_key, recipient_priv)

    # Decrypt body
    plaintext = aes_decrypt(enc_body, aes_key, iv)

    # Verify signature
    valid = verify_signature(plaintext, sig, sender_pub)

    return plaintext.decode(), valid

def main():
    print("=" * 65)
    print("      EMAIL ENCRYPTION AND SIGNING (PGP-style)")
    print("=" * 65)
    print("Generating RSA key pairs for Alice (sender) and Bob (recipient)...")
    alice_priv, alice_pub = generate_keypair(1024)
    bob_priv,   bob_pub   = generate_keypair(1024)
    print("Key pairs generated.")

    print("\n1. Alice sends encrypted+signed email to Bob")
    print("2. Bob decrypts and verifies")
    print("3. Full demo (send + receive + tamper test)")
    choice = input("Choice: ").strip()

    if choice == '1':
        subject = input("Enter email subject: ")
        body    = input("Enter email body: ")
        envelope = encrypt_email(subject, body, alice_priv, bob_pub)
        env_data = json.loads(envelope)
        print(f"\n--- Encrypted Email Envelope ---")
        print(f"Encrypted Session Key : {env_data['encrypted_key'][:48]}...")
        print(f"IV (base64)           : {env_data['iv']}")
        print(f"Encrypted Body        : {env_data['encrypted_body'][:48]}...")
        print(f"Alice's Signature     : {env_data['signature'][:48]}...")
        with open("email.json", "w") as f:
            f.write(envelope)
        print("\nEnvelope saved to email.json")

    elif choice == '2':
        with open("email.json", "r") as f:
            envelope = f.read()
        plaintext, valid = decrypt_email(envelope, bob_priv, alice_pub)
        print(f"\n--- Decrypted Email ---")
        print(plaintext)
        print(f"\nSignature valid: {'✓ YES' if valid else '✗ NO'}")

    elif choice == '3':
        subject = input("Enter subject: ")
        body    = input("Enter body: ")
        print("\nAlice encrypts and signs...")
        envelope = encrypt_email(subject, body, alice_priv, bob_pub)
        print("Envelope created.")

        print("\nBob decrypts and verifies...")
        pt, valid = decrypt_email(envelope, bob_priv, alice_pub)
        print(f"Decrypted:\n{pt}")
        print(f"Signature: {'✓ VALID' if valid else '✗ INVALID'}")

        print("\n--- Tamper Simulation ---")
        env = json.loads(envelope)
        enc_body = base64.b64decode(env['encrypted_body'])
        # Flip a byte in encrypted body
        tampered = bytearray(enc_body)
        tampered[10] ^= 0xFF
        env['encrypted_body'] = base64.b64encode(bytes(tampered)).decode()
        tampered_envelope = json.dumps(env)
        try:
            pt2, valid2 = decrypt_email(tampered_envelope, bob_priv, alice_pub)
            print(f"Decrypted (tampered) : {pt2[:60]}...")
            print(f"Signature (tampered) : {'✓ VALID' if valid2 else '✗ INVALID - Tamper Detected!'}")
        except Exception as e:
            print(f"Decryption failed after tampering: {e}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
