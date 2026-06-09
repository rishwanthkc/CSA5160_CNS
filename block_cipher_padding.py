"""
CSA51 - Program 15: Block Cipher Padding Scheme
Demonstrates PKCS#7 padding, Zero padding, and ANSI X.923 padding.
"""

BLOCK_SIZE = 16

def pkcs7_pad(data, block_size=BLOCK_SIZE):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len > BLOCK_SIZE or pad_len == 0:
        raise ValueError("Invalid PKCS#7 padding.")
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]

def zero_pad(data, block_size=BLOCK_SIZE):
    pad_len = block_size - (len(data) % block_size)
    return data + b'\x00' * pad_len

def zero_unpad(data):
    return data.rstrip(b'\x00')

def ansi_x923_pad(data, block_size=BLOCK_SIZE):
    pad_len = block_size - (len(data) % block_size)
    return data + b'\x00' * (pad_len - 1) + bytes([pad_len])

def ansi_x923_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def hex_display(data):
    return ' '.join(f'{b:02X}' for b in data)

def main():
    print("=" * 60)
    print("       BLOCK CIPHER PADDING SCHEMES")
    print("=" * 60)
    print(f"Block size: {BLOCK_SIZE} bytes")
    print()
    text = input("Enter plaintext: ")
    data = text.encode('utf-8')

    print(f"\nOriginal Data ({len(data)} bytes): {hex_display(data)}")
    print(f"Printable: {text}")

    # PKCS#7
    padded_pkcs7 = pkcs7_pad(data)
    print(f"\n--- PKCS#7 Padding ---")
    print(f"Padded ({len(padded_pkcs7)} bytes): {hex_display(padded_pkcs7)}")
    print(f"Padding added: {padded_pkcs7[-1]} bytes of value 0x{padded_pkcs7[-1]:02X}")
    unpadded = pkcs7_unpad(padded_pkcs7)
    print(f"After unpad: {unpadded.decode()}")

    # Zero Padding
    padded_zero = zero_pad(data)
    print(f"\n--- Zero (Null) Padding ---")
    print(f"Padded ({len(padded_zero)} bytes): {hex_display(padded_zero)}")
    unpadded_z = zero_unpad(padded_zero)
    print(f"After unpad: {unpadded_z.decode()}")

    # ANSI X.923
    padded_ansi = ansi_x923_pad(data)
    print(f"\n--- ANSI X.923 Padding ---")
    print(f"Padded ({len(padded_ansi)} bytes): {hex_display(padded_ansi)}")
    print(f"Last byte (length indicator): 0x{padded_ansi[-1]:02X}")
    unpadded_a = ansi_x923_unpad(padded_ansi)
    print(f"After unpad: {unpadded_a.decode()}")

    print(f"\n--- Summary ---")
    print(f"Original length  : {len(data)} bytes")
    print(f"PKCS#7 padded    : {len(padded_pkcs7)} bytes")
    print(f"Zero padded      : {len(padded_zero)} bytes")
    print(f"ANSI X.923 padded: {len(padded_ansi)} bytes")

if __name__ == "__main__":
    main()
