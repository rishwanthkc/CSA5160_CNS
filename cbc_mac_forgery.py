"""
CSA51 - Program 23: CBC-MAC Forgery Analysis
Demonstrates the length-extension forgery attack on CBC-MAC.
"""
try:
    from Crypto.Cipher import AES
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.Cipher import AES
import os

BLOCK = 16

def cbc_mac(key, message):
    """Compute CBC-MAC of a message (must be block-aligned)."""
    assert len(message) % BLOCK == 0, "Message must be block-aligned."
    iv = b'\x00' * BLOCK
    prev = iv
    for i in range(0, len(message), BLOCK):
        block = bytes(x ^ y for x, y in zip(message[i:i+BLOCK], prev))
        cipher = AES.new(key, AES.MODE_ECB)
        prev = cipher.encrypt(block)
    return prev

def pad_to_block(data):
    pad_len = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad_len] * pad_len)

def main():
    print("=" * 65)
    print("          CBC-MAC FORGERY ANALYSIS")
    print("=" * 65)
    print("CBC-MAC is secure for fixed-length messages but vulnerable")
    print("to length-extension attacks for variable-length messages.")

    key = os.urandom(16)
    print(f"\nKey (hex): {key.hex()} [secret, shown for demo]")

    m1_text = input("\nEnter Message 1 (m1): ").encode()
    m1 = pad_to_block(m1_text)
    mac1 = cbc_mac(key, m1)
    print(f"m1 (padded hex) : {m1.hex()}")
    print(f"MAC(m1)         : {mac1.hex()}")

    m2_text = input("Enter Message 2 (m2): ").encode()
    m2 = pad_to_block(m2_text)
    mac2 = cbc_mac(key, m2)
    print(f"\nm2 (padded hex) : {m2.hex()}")
    print(f"MAC(m2)         : {mac2.hex()}")

    # Forgery: attacker knows m1 and mac1, constructs m1 || (m2 XOR mac1)
    print("\n--- Length-Extension Forgery Attempt ---")
    m2_forged = bytes(x ^ y for x, y in zip(m2[:BLOCK], mac1)) + m2[BLOCK:]
    forged_message = m1 + m2_forged
    forged_mac = cbc_mac(key, forged_message)

    print(f"Forged message (m1 || m2'): {forged_message.hex()}")
    print(f"Forged MAC                : {forged_mac.hex()}")
    print(f"MAC(m2) for comparison    : {mac2.hex()}")

    if forged_mac == mac2:
        print("\n[!] FORGERY SUCCEEDED: forged_mac == MAC(m2)")
        print("This shows CBC-MAC is insecure for variable-length messages!")
    else:
        print("\nForgery failed (try single-block messages).")

    print("\n--- Defense: CMAC/HMAC is the recommended alternative ---")

if __name__ == "__main__":
    main()
