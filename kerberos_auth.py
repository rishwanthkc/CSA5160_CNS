"""
CSA51 - Program 34: Authentication using Kerberos
Simulates the Kerberos authentication protocol: AS, TGS, and Service.
"""
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()[:16]

def encrypt(key, plaintext):
    """Simple XOR encryption for demo (not real Kerberos AES)."""
    key_bytes = key
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

def decrypt(key, ciphertext):
    return encrypt(key, ciphertext)  # XOR is symmetric

def hmac_auth(key, data):
    return hmac.new(key, data if isinstance(data, bytes) else data.encode(), hashlib.sha256).digest()[:8]

def format_ticket(ticket):
    return {k: (v.hex() if isinstance(v, bytes) else v) for k, v in ticket.items()}

class KDC:
    """Key Distribution Center = AS + TGS combined."""
    def __init__(self):
        self.users = {}
        self.services = {}
        self.tgt_key = os.urandom(16)  # TGS session key (secret)
        print("KDC initialized.")

    def register_user(self, username, password):
        self.users[username] = derive_key(password)
        print(f"User '{username}' registered.")

    def register_service(self, service_name, password):
        self.services[service_name] = derive_key(password)
        print(f"Service '{service_name}' registered.")

    def authenticate(self, username, password):
        """AS Exchange: Client → AS, AS → Client (TGT)."""
        key = self.users.get(username)
        if not key:
            return None, "User not found."
        if derive_key(password) != key:
            return None, "Authentication failed."

        # TGT: Ticket Granting Ticket
        session_key = os.urandom(16)
        expiry = (datetime.now() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M")
        tgt = {
            'client': username,
            'issued': datetime.now().strftime("%Y-%m-%d %H:%M"),
            'expiry': expiry,
            'session_key': session_key.hex(),
        }
        tgt_serialized = str(tgt).encode()
        encrypted_tgt = encrypt(self.tgt_key, tgt_serialized)
        encrypted_session = encrypt(key, session_key)

        return {
            'encrypted_tgt': encrypted_tgt,
            'encrypted_session_key': encrypted_session,
            'session_key': session_key,  # given to client
            'expiry': expiry
        }, "AS: Authentication successful. TGT issued."

    def get_service_ticket(self, encrypted_tgt, session_key, service_name, username):
        """TGS Exchange: Client → TGS, TGS → Client (Service Ticket)."""
        tgt_data = decrypt(self.tgt_key, encrypted_tgt).decode(errors='replace')

        if service_name not in self.services:
            return None, "Service not found."

        service_key = self.services[service_name]
        svc_session_key = os.urandom(16)
        expiry = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
        service_ticket = {
            'client': username,
            'service': service_name,
            'expiry': expiry,
            'svc_session_key': svc_session_key.hex(),
        }
        st_serialized = str(service_ticket).encode()
        encrypted_st = encrypt(service_key, st_serialized)
        encrypted_svc_session = encrypt(session_key, svc_session_key)

        return {
            'encrypted_service_ticket': encrypted_st,
            'encrypted_svc_session_key': encrypted_svc_session,
            'svc_session_key': svc_session_key,
            'expiry': expiry
        }, "TGS: Service ticket issued."

    def verify_service_ticket(self, encrypted_st, service_name, username):
        """Service Server: Validates the service ticket."""
        if service_name not in self.services:
            return False, "Service not found."
        service_key = self.services[service_name]
        st_data = decrypt(service_key, encrypted_st).decode(errors='replace')
        if username in st_data and service_name in st_data:
            return True, "Service: Ticket verified. Access granted."
        return False, "Service: Invalid ticket. Access denied."

def main():
    print("=" * 65)
    print("       KERBEROS AUTHENTICATION SIMULATION")
    print("=" * 65)

    kdc = KDC()

    # Setup
    print("\n--- Setup Phase ---")
    kdc.register_user("alice", "alice_password")
    kdc.register_service("fileserver", "fs_secret")
    kdc.register_service("mailserver", "ms_secret")

    print("\n--- Step 1: User Login (AS Exchange) ---")
    username = input("Enter username: ")
    password = input("Enter password: ")

    result, msg = kdc.authenticate(username, password)
    print(f"Status: {msg}")
    if not result:
        return

    print(f"TGT received (encrypted): {result['encrypted_tgt'].hex()[:32]}...")
    print(f"Session Key (hex)       : {result['session_key'].hex()}")
    print(f"Ticket valid until      : {result['expiry']}")

    print("\n--- Step 2: Request Service Ticket (TGS Exchange) ---")
    print("Available services: fileserver, mailserver")
    service = input("Enter service name: ").strip()

    st_result, st_msg = kdc.get_service_ticket(
        result['encrypted_tgt'],
        result['session_key'],
        service, username
    )
    print(f"Status: {st_msg}")
    if not st_result:
        return

    print(f"Service Ticket (encrypted): {st_result['encrypted_service_ticket'].hex()[:32]}...")
    print(f"Service Session Key: {st_result['svc_session_key'].hex()}")

    print("\n--- Step 3: Access Service ---")
    ok, svc_msg = kdc.verify_service_ticket(
        st_result['encrypted_service_ticket'], service, username
    )
    print(f"Status: {svc_msg}")
    if ok:
        print(f"\n✓ {username} is now authenticated and connected to {service}!")
    else:
        print(f"✗ Access denied to {service}.")

if __name__ == "__main__":
    main()
