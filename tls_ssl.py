"""
CSA51 - Program 31: Implement TLS/SSL
Demonstrates TLS/SSL concepts using Python's ssl module with a simple server/client.
Run this script and choose server or client mode.
"""
import ssl
import socket
import threading
import os
import subprocess
import sys

CERT_FILE = "server.crt"
KEY_FILE  = "server.key"
HOST = "127.0.0.1"
PORT = 8443

def generate_self_signed_cert():
    if not os.path.exists(CERT_FILE):
        print("Generating self-signed certificate...")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost/O=CSA51Lab/C=IN"
        ], capture_output=True)
        print(f"Certificate: {CERT_FILE}, Key: {KEY_FILE}")

def print_tls_info(conn, side):
    cipher = conn.cipher()
    cert   = conn.getpeercert()
    proto  = conn.version()
    print(f"\n--- TLS Session Info ({side}) ---")
    print(f"Protocol : {proto}")
    print(f"Cipher   : {cipher[0] if cipher else 'N/A'}")
    print(f"Bits     : {cipher[2] if cipher else 'N/A'}")
    print(f"Peer Cert: {'Present' if cert else 'None (self-signed, not verified)'}")

def tls_server():
    generate_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        print(f"TLS Server listening on {HOST}:{PORT}")
        print("Waiting for client connection...")
        conn_sock, addr = sock.accept()
        with ctx.wrap_socket(conn_sock, server_side=True) as tls_conn:
            print(f"Client connected from {addr}")
            print_tls_info(tls_conn, "Server")
            data = tls_conn.recv(4096)
            print(f"\nReceived (encrypted over TLS): {data.decode()}")
            response = f"Hello from TLS Server! Your message: '{data.decode()}'"
            tls_conn.sendall(response.encode())
            print(f"Sent response.")

def tls_client():
    generate_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # For self-signed demo only

    msg = input("Enter message to send to server: ")
    with socket.create_connection((HOST, PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as tls_conn:
            print_tls_info(tls_conn, "Client")
            tls_conn.sendall(msg.encode())
            print(f"\nSent: {msg}")
            response = tls_conn.recv(4096)
            print(f"Received: {response.decode()}")

def tls_info():
    print("\n--- TLS/SSL Overview ---")
    print("""
TLS (Transport Layer Security) - successor to SSL:

Handshake Steps:
  1. ClientHello  → Client sends supported TLS versions, ciphers, random nonce
  2. ServerHello  → Server selects cipher, sends certificate + random nonce
  3. Key Exchange → Client/Server derive session keys (via RSA or ECDHE)
  4. Finished     → Both sides verify handshake integrity with MAC
  5. Data         → All data encrypted with symmetric keys (AES-GCM etc.)

TLS Record Protocol: Provides confidentiality + integrity for all data.
Certificate: Binds server's public key to its identity (signed by CA).
    """)
    ctx = ssl.create_default_context()
    print(f"Python SSL Version : {ssl.OPENSSL_VERSION}")
    print(f"Default ciphers    : {len(ctx.get_ciphers())} supported")
    for c in ctx.get_ciphers()[:5]:
        print(f"  {c['name']}")
    print("  ... and more")

def main():
    print("=" * 60)
    print("          TLS/SSL IMPLEMENTATION DEMO")
    print("=" * 60)
    print("\n1. Run as TLS Server (run this first in one terminal)")
    print("2. Run as TLS Client (run in another terminal)")
    print("3. Show TLS/SSL information and concepts")
    choice = input("Choice (1/2/3): ").strip()

    if choice == '1':
        tls_server()
    elif choice == '2':
        tls_client()
    elif choice == '3':
        tls_info()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
