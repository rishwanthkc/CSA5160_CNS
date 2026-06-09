"""
CSA51 - Program 40: Analyse Session Tokens
Demonstrates session token generation, JWT structure, and common vulnerabilities.
"""
import os
import json
import hmac
import hashlib
import base64
import time
from datetime import datetime, timedelta

# ─── Base64URL ──────────────────────────────────────────────────
def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

# ─── JWT ────────────────────────────────────────────────────────
def create_jwt(payload, secret, algo='HS256'):
    header = {"alg": algo, "typ": "JWT"}
    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    signing_input = f"{h}.{p}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"

def decode_jwt(token, secret=None, verify=True):
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, "Invalid JWT format"
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = b64url_decode(parts[2])

    if verify and secret:
        expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        valid = hmac.compare_digest(sig, expected)
        if not valid:
            return header, payload, "INVALID SIGNATURE"
    return header, payload, "OK"

def check_jwt_expiry(payload):
    exp = payload.get('exp')
    if not exp:
        return "No expiry claim"
    now = int(time.time())
    if now > exp:
        return f"EXPIRED at {datetime.utcfromtimestamp(exp)}"
    return f"Valid until {datetime.utcfromtimestamp(exp)} ({exp - now}s remaining)"

# ─── Session Token Generator ─────────────────────────────────────
def generate_session_token(method='random'):
    if method == 'random':
        return os.urandom(32).hex()
    elif method == 'hmac':
        user_id = os.urandom(4).hex()
        ts = str(int(time.time()))
        sig = hmac.new(b'secret_key', f"{user_id}{ts}".encode(), hashlib.sha256).hexdigest()[:16]
        return f"{user_id}-{ts}-{sig}"
    elif method == 'uuid':
        import uuid
        return str(uuid.uuid4())

# ─── Vulnerability Demos ─────────────────────────────────────────
def demo_alg_none_attack(token, secret):
    print("\n--- JWT 'alg:none' Attack ---")
    parts = token.split('.')
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    header['alg'] = 'none'
    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    forged = f"{h}.{p}."
    print(f"Forged token (alg=none): {forged[:60]}...")
    print("Defense: Always verify algorithm server-side. Reject 'none' algo.")

def demo_weak_secret_crack(token):
    print("\n--- Weak Secret Brute Force ---")
    wordlist = ['secret', 'password', '123456', 'admin', 'key', 'jwt_secret', 'myapp']
    parts = token.split('.')
    for word in wordlist:
        sig_check = hmac.new(word.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if b64url_encode(sig_check) == parts[2]:
            print(f"CRACKED! Secret = '{word}'")
            return word
    print("Secret not in simple wordlist.")
    return None

def main():
    print("=" * 65)
    print("           SESSION TOKEN ANALYSIS")
    print("=" * 65)
    print("1. Generate session tokens")
    print("2. Create and decode JWT")
    print("3. JWT security analysis")
    print("4. Session token vulnerability demos")
    choice = input("Choice: ").strip()

    if choice == '1':
        print("\n--- Session Token Generation Methods ---")
        for method in ['random', 'hmac', 'uuid']:
            token = generate_session_token(method)
            print(f"{method.upper():<8}: {token}")
        print("\nBest practice: Use cryptographically random tokens (≥128 bits).")

    elif choice == '2':
        secret = input("Enter JWT secret key: ")
        username = input("Enter username: ")
        role = input("Enter role (user/admin): ") or "user"
        expiry_mins = int(input("Token expiry in minutes: ") or "30")

        payload = {
            'sub': username,
            'role': role,
            'iat': int(time.time()),
            'exp': int(time.time()) + expiry_mins * 60,
        }
        token = create_jwt(payload, secret)
        print(f"\nGenerated JWT:\n{token}")

        parts = token.split('.')
        print(f"\nHeader  : {b64url_decode(parts[0]).decode()}")
        print(f"Payload : {b64url_decode(parts[1]).decode()}")
        print(f"Signature: {parts[2][:32]}...")

        print("\n--- Verifying JWT ---")
        header, decoded_payload, status = decode_jwt(token, secret)
        print(f"Status  : {status}")
        print(f"Expiry  : {check_jwt_expiry(decoded_payload)}")

    elif choice == '3':
        token = input("Paste JWT to analyse: ").strip()
        parts = token.split('.')
        if len(parts) != 3:
            print("Not a valid JWT.")
            return
        print(f"\n--- JWT Structure ---")
        try:
            header  = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            print(f"Header  : {json.dumps(header, indent=2)}")
            print(f"Payload : {json.dumps(payload, indent=2)}")
        except Exception as e:
            print(f"Parse error: {e}")
            return

        print("\n--- Security Checks ---")
        algo = header.get('alg','')
        if algo == 'none':
            print("  ✗ CRITICAL: alg=none! No signature verification.")
        elif algo in ('HS256','HS384','HS512'):
            print(f"  ✓ Algorithm: {algo} (HMAC-based)")
        elif algo in ('RS256','RS384','RS512'):
            print(f"  ✓ Algorithm: {algo} (RSA-based)")
        else:
            print(f"  ? Unknown algorithm: {algo}")

        if 'exp' not in payload:
            print("  ✗ WARNING: No expiry (exp) claim!")
        else:
            print(f"  ✓ Expiry: {check_jwt_expiry(payload)}")
        if 'iat' not in payload:
            print("  ⚠ No issued-at (iat) claim.")
        if 'sub' in payload:
            print(f"  ✓ Subject (sub): {payload['sub']}")

    elif choice == '4':
        secret = input("Enter JWT secret (use a weak one like 'secret'): ")
        payload = {'sub': 'alice', 'role': 'user', 'exp': int(time.time())+3600}
        token = create_jwt(payload, secret)
        print(f"\nToken: {token[:60]}...")
        demo_alg_none_attack(token, secret)
        demo_weak_secret_crack(token)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
