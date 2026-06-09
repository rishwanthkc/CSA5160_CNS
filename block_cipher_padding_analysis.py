"""
CSA51 - Program 27: Block Cipher Padding Analysis
Analyzes different padding schemes and demonstrates padding oracle concept.
"""
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
import os

BLOCK = 16

def analyze_padding(data, block_size=16):
    last_byte = data[-1]
    if last_byte == 0 or last_byte > block_size:
        return "Invalid PKCS#7 padding"
    pad_bytes = data[-last_byte:]
    if all(b == last_byte for b in pad_bytes):
        return f"PKCS#7 padding: {last_byte} byte(s) of value 0x{last_byte:02X}"
    return "Invalid PKCS#7 padding"

def pkcs7_pad(data):
    pad_len = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad_len] * pad_len)

def simulate_padding_oracle(key, iv, ciphertext):
    """Simulates a server that reveals if padding is valid (insecure!)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ciphertext), BLOCK)
        return True
    except (ValueError, KeyError):
        return False

def padding_oracle_demo(key, iv, ciphertext):
    """Demonstrate 1 byte of padding oracle attack."""
    print("\n--- Padding Oracle Attack Demo (1 byte of last block) ---")
    C1 = bytearray(ciphertext[-2*BLOCK:-BLOCK])  # Second to last block
    C2 = ciphertext[-BLOCK:]                       # Last block

    print(f"Target block C2: {C2.hex()}")
    print(f"Previous block C1: {C1.hex()}")
    print(f"\nAttempting to recover last byte of penultimate plaintext block...")

    found = False
    for guess in range(256):
        C1_mod = bytearray(C1)
        C1_mod[-1] ^= guess ^ 0x01  # Force last padding byte to be 0x01
        modified_ct = bytes(C1_mod) + C2
        if simulate_padding_oracle(key, iv, modified_ct):
            intermediate = guess
            # P[last] = intermediate XOR C1_original[-1]
            pt_byte = intermediate ^ C1[-1]
            print(f"  Found! Guess={guess}, Intermediate={intermediate}, Plaintext byte = 0x{pt_byte:02X} ('{chr(pt_byte) if 32<=pt_byte<127 else '?'}')")
            found = True
            break
    if not found:
        print("  Could not determine (try longer message).")

def main():
    print("=" * 65)
    print("        BLOCK CIPHER PADDING ANALYSIS")
    print("=" * 65)

    print("1. Analyze padding of given data")
    print("2. Encrypt and show padding details")
    print("3. Padding Oracle demo")
    choice = input("Choice (1/2/3): ").strip()

    if choice == '1':
        hex_data = input("Enter hex data to analyze: ").strip()
        data = bytes.fromhex(hex_data)
        print(f"\nData ({len(data)} bytes): {hex_data}")
        print(f"Last byte: 0x{data[-1]:02X}")
        print(f"Analysis: {analyze_padding(data)}")

    elif choice == '2':
        text = input("Enter plaintext: ").encode()
        padded = pkcs7_pad(text)
        print(f"\nOriginal ({len(text)} bytes): {text.hex()}")
        print(f"Padded   ({len(padded)} bytes): {padded.hex()}")
        print(f"Padding bytes: {padded[-padded[-1]:]}")
        print(f"Analysis: {analyze_padding(padded)}")

        key = os.urandom(16)
        iv  = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(padded)
        print(f"\nEncrypted (AES-CBC): {ct.hex()}")
        valid = simulate_padding_oracle(key, iv, ct)
        print(f"Padding valid: {valid}")

    elif choice == '3':
        text = input("Enter plaintext (will be encrypted): ").encode()
        while len(text) < BLOCK:
            text += b'X'
        key = os.urandom(16)
        iv  = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(text, BLOCK))
        print(f"\nCiphertext: {ct.hex()}")
        padding_oracle_demo(key, iv, ct)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
