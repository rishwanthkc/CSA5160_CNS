"""
CSA51 - Program 39: Analyse HTTPS Traffic
Demonstrates HTTPS traffic analysis: TLS handshake simulation,
certificate inspection, and traffic characteristics.
"""
import ssl
import socket
import json
import datetime

def get_server_certificate(hostname, port=443):
    """Retrieve and analyze a server's TLS certificate."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
                return cert, cipher, proto, None
    except Exception as e:
        return None, None, None, str(e)

def analyze_certificate(cert):
    if not cert:
        return
    print("\n--- Certificate Details ---")
    subject = dict(x[0] for x in cert.get('subject', []))
    issuer  = dict(x[0] for x in cert.get('issuer', []))
    print(f"  Subject CN     : {subject.get('commonName', 'N/A')}")
    print(f"  Subject Org    : {subject.get('organizationName', 'N/A')}")
    print(f"  Issuer CN      : {issuer.get('commonName', 'N/A')}")
    print(f"  Issuer Org     : {issuer.get('organizationName', 'N/A')}")
    not_before = cert.get('notBefore', 'N/A')
    not_after  = cert.get('notAfter', 'N/A')
    print(f"  Valid From     : {not_before}")
    print(f"  Valid Until    : {not_after}")
    sans = cert.get('subjectAltName', [])
    if sans:
        print(f"  SANs           : {', '.join(v for _, v in sans[:5])}")
    serial = cert.get('serialNumber', 'N/A')
    print(f"  Serial Number  : {serial}")

    # Check expiry
    try:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.datetime.utcnow()).days
        status = "✓ Valid" if days_left > 0 else "✗ EXPIRED"
        print(f"  Days Until Exp : {days_left} [{status}]")
    except Exception:
        pass

def analyze_tls_session(cipher, proto):
    if not cipher:
        return
    print("\n--- TLS Session Details ---")
    print(f"  TLS Version    : {proto}")
    print(f"  Cipher Suite   : {cipher[0]}")
    print(f"  Key Bits       : {cipher[2]}")

    # Security assessment
    warnings = []
    if proto in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
        warnings.append(f"Outdated TLS version: {proto}")
    if cipher[2] and cipher[2] < 128:
        warnings.append(f"Weak key size: {cipher[2]} bits")
    if 'RC4' in (cipher[0] or ''):
        warnings.append("RC4 cipher is insecure!")
    if 'NULL' in (cipher[0] or ''):
        warnings.append("NULL cipher: no encryption!")

    if warnings:
        print(f"\n  ⚠ SECURITY WARNINGS:")
        for w in warnings:
            print(f"     - {w}")
    else:
        print(f"\n  ✓ TLS configuration looks secure.")

def simulate_https_request():
    """Simulate an HTTPS GET request structure."""
    print("\n--- HTTPS Request Structure (Simulated) ---")
    print("""
[TCP 3-Way Handshake]
  Client → Server: SYN
  Server → Client: SYN-ACK
  Client → Server: ACK

[TLS Handshake]
  Client → Server: ClientHello (TLS 1.3, supported ciphers, random)
  Server → Client: ServerHello (chosen cipher, random)
  Server → Client: Certificate (X.509)
  Server → Client: ServerHelloDone
  Client → Server: ClientKeyExchange (Pre-master secret, encrypted)
  Client → Server: ChangeCipherSpec
  Client → Server: Finished (Encrypted)
  Server → Client: ChangeCipherSpec
  Server → Client: Finished (Encrypted)

[HTTPS Data Transfer - All Encrypted with Session Keys]
  Client → Server: HTTP GET /page HTTP/1.1
                   Host: example.com
                   [AES-GCM Encrypted]
  Server → Client: HTTP/1.1 200 OK
                   Content-Type: text/html
                   [AES-GCM Encrypted]

[Connection Close]
  Client → Server: TLS Alert: close_notify
  Server → Client: TLS Alert: close_notify
    """)

def check_http_vs_https():
    print("\n--- HTTP vs HTTPS Comparison ---")
    comparison = [
        ("Feature",         "HTTP",          "HTTPS"),
        ("Port",            "80",             "443"),
        ("Encryption",      "None",           "TLS/SSL"),
        ("Authentication",  "None",           "Certificate (CA-signed)"),
        ("Integrity",       "None",           "HMAC/AEAD"),
        ("Confidentiality", "No",             "Yes"),
        ("Performance",     "Faster",         "Slight overhead (ms)"),
        ("SEO",             "Penalized",      "Preferred by Google"),
        ("Use case",        "Internal/legacy","All public web traffic"),
    ]
    for row in comparison:
        print(f"  {row[0]:<18} {row[1]:<20} {row[2]}")

def main():
    print("=" * 65)
    print("           HTTPS TRAFFIC ANALYSIS")
    print("=" * 65)
    print("1. Connect to a real HTTPS server and inspect certificate")
    print("2. Simulate TLS handshake flow")
    print("3. HTTP vs HTTPS comparison")
    choice = input("Choice: ").strip()

    if choice == '1':
        hostname = input("Enter hostname (e.g. www.google.com): ").strip()
        port = int(input("Port (default 443): ").strip() or "443")
        print(f"\nConnecting to {hostname}:{port}...")
        cert, cipher, proto, err = get_server_certificate(hostname, port)
        if err:
            print(f"Error: {err}")
        else:
            print(f"✓ Connected successfully!")
            analyze_tls_session(cipher, proto)
            analyze_certificate(cert)

    elif choice == '2':
        simulate_https_request()

    elif choice == '3':
        check_http_vs_https()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
