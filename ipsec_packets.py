"""
CSA51 - Program 32: Analyse IPsec Packets
Demonstrates IPsec AH and ESP packet structure parsing and simulation.
"""
import struct
import hashlib
import hmac
import os

def compute_ah_icv(data, key):
    """Authentication Header ICV using HMAC-SHA1."""
    return hmac.new(key, data, hashlib.sha1).digest()[:12]

def build_ah_header(next_header, payload_len, spi, seq, icv):
    """Build AH header bytes."""
    ah = struct.pack("!BBHII", next_header, payload_len, 0, spi, seq)
    return ah + icv

def parse_ah(data):
    """Parse Authentication Header."""
    if len(data) < 12:
        return None
    next_hdr, plen, reserved, spi, seq = struct.unpack("!BBHII", data[:12])
    icv_len = (plen - 1) * 4
    icv = data[12:12+icv_len]
    payload = data[12+icv_len:]
    return {'next_header': next_hdr, 'payload_len': plen, 'spi': spi,
            'seq': seq, 'icv': icv.hex(), 'payload': payload}

def build_esp_packet(spi, seq, payload, key_enc, key_auth):
    """Build ESP packet with AES-style XOR encryption (demo) + HMAC auth."""
    # Pad payload to block boundary
    pad_len = (4 - len(payload) % 4) % 4
    padded = payload + b'\x00' * pad_len + bytes([pad_len, 59])  # 59 = no next header

    # Encrypt payload (XOR with key for demo - not real AES)
    iv = os.urandom(8)
    key_bytes = key_enc.encode()[:8].ljust(8, b'\x00')
    encrypted = bytes(b ^ key_bytes[i % 8] for i, b in enumerate(padded))

    header = struct.pack("!II", spi, seq)
    esp_body = header + iv + encrypted

    # Auth
    icv = hmac.new(key_auth.encode(), esp_body, hashlib.sha256).digest()[:12]
    return esp_body + icv, iv

def parse_esp(data):
    """Parse ESP packet."""
    if len(data) < 8:
        return None
    spi, seq = struct.unpack("!II", data[:8])
    iv = data[8:16]
    payload_with_icv = data[16:]
    icv = payload_with_icv[-12:]
    encrypted_payload = payload_with_icv[:-12]
    return {'spi': spi, 'seq': seq, 'iv': iv.hex(),
            'encrypted_len': len(encrypted_payload), 'icv': icv.hex()}

def demo_ipsec_modes():
    print("\n--- IPsec Mode Overview ---")
    print("""
Transport Mode:
  [IP Header] [AH/ESP] [Transport (TCP/UDP)] [Payload]
  - Protects only the payload
  - IP header is NOT protected (in AH) or modified (in ESP)
  - Used: end-to-end between two hosts

Tunnel Mode:
  [New IP Header] [AH/ESP] [Original IP Header] [Transport] [Payload]
  - Entire original packet is encapsulated
  - Used: VPNs, gateway-to-gateway
    """)

def main():
    print("=" * 65)
    print("           ANALYSE IPSEC PACKETS")
    print("=" * 65)
    print("1. Simulate and analyse AH (Authentication Header)")
    print("2. Simulate and analyse ESP (Encapsulating Security Payload)")
    print("3. Show IPsec modes (Transport vs Tunnel)")
    choice = input("Choice (1/2/3): ").strip()

    if choice == '1':
        print("\n--- Authentication Header (AH) ---")
        print("AH provides: integrity + authentication (NO confidentiality)")
        payload = input("Enter payload (will be protected): ").encode()
        key = os.urandom(16)
        spi = int(input("Enter SPI (Security Parameter Index, e.g. 1234): "))
        seq = int(input("Enter sequence number (e.g. 1): "))

        icv = compute_ah_icv(payload, key)
        ah = build_ah_header(6, 4, spi, seq, icv)

        print(f"\nAH Header Analysis:")
        print(f"  Next Header  : {ah[0]} (TCP=6)")
        print(f"  Payload Len  : {ah[1]}")
        print(f"  SPI          : {spi}")
        print(f"  Sequence No  : {seq}")
        print(f"  ICV (12 bytes): {icv.hex()}")
        print(f"  Protected data: {payload.hex()}")

        # Tamper test
        tampered = bytearray(payload)
        tampered[0] ^= 0xFF
        icv2 = compute_ah_icv(bytes(tampered), key)
        print(f"\nTampered ICV: {icv2.hex()}")
        print(f"ICV match: {'✓' if icv == icv2 else '✗ Tamper Detected!'}")

    elif choice == '2':
        print("\n--- Encapsulating Security Payload (ESP) ---")
        print("ESP provides: confidentiality + integrity + authentication")
        payload = input("Enter payload: ").encode()
        spi = int(input("Enter SPI (e.g. 5678): "))
        seq = int(input("Enter sequence number: "))
        key_enc  = input("Enter encryption key (string): ")
        key_auth = input("Enter auth key (string): ")

        packet, iv = build_esp_packet(spi, seq, payload, key_enc, key_auth)
        parsed = parse_esp(packet)

        print(f"\nESP Packet ({len(packet)} bytes):")
        print(f"  SPI              : {parsed['spi']}")
        print(f"  Sequence Number  : {parsed['seq']}")
        print(f"  IV               : {parsed['iv']}")
        print(f"  Encrypted Payload: {parsed['encrypted_len']} bytes")
        print(f"  ICV (12 bytes)   : {parsed['icv']}")
        print(f"  Full packet (hex): {packet.hex()}")

    elif choice == '3':
        demo_ipsec_modes()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
