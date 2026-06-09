"""
CSA51 - Program 24: CMAC Subkey Generation
Demonstrates CMAC (Cipher-based MAC) subkey generation and MAC computation.
"""
try:
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
except ImportError:
    import subprocess
    subprocess.run(["pip","install","pycryptodome","--break-system-packages","-q"])
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
import os

BLOCK = 16
Rb = 0x87  # CMAC constant for 128-bit block cipher

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def left_shift_1(b):
    n = int.from_bytes(b, 'big')
    shifted = ((n << 1) & ((1 << 128) - 1))
    return shifted.to_bytes(16, 'big')

def generate_subkeys(key):
    cipher = AES.new(key, AES.MODE_ECB)
    L = cipher.encrypt(b'\x00' * BLOCK)
    print(f"L = AES_K(0^128) = {L.hex()}")

    # K1
    if L[0] & 0x80 == 0:
        K1 = left_shift_1(L)
    else:
        K1 = xor_bytes(left_shift_1(L), b'\x00'*15 + bytes([Rb]))

    # K2
    if K1[0] & 0x80 == 0:
        K2 = left_shift_1(K1)
    else:
        K2 = xor_bytes(left_shift_1(K1), b'\x00'*15 + bytes([Rb]))

    print(f"K1 = {K1.hex()}")
    print(f"K2 = {K2.hex()}")
    return K1, K2

def compute_cmac_manual(key, message):
    K1, K2 = generate_subkeys(key)

    # Padding
    n = (len(message) + BLOCK - 1) // BLOCK if message else 1
    complete = len(message) == n * BLOCK and len(message) > 0

    blocks = [message[i*BLOCK:(i+1)*BLOCK] for i in range(n)] if n > 0 else [b'']
    if not blocks:
        blocks = [b'']

    # Last block processing
    last = blocks[-1]
    if complete:
        last_block = xor_bytes(last, K1)
    else:
        padded = last + b'\x80' + b'\x00' * (BLOCK - len(last) - 1)
        last_block = xor_bytes(padded, K2)

    blocks[-1] = last_block

    # CBC pass
    X = b'\x00' * BLOCK
    cipher = AES.new(key, AES.MODE_ECB)
    print(f"\n{'Block':<6} {'Input':<35} {'X (after XOR)':<35} {'T (after AES)'}")
    print("-" * 110)
    for i, blk in enumerate(blocks):
        xored = xor_bytes(blk, X)
        X = cipher.encrypt(xored)
        print(f"{i+1:<6} {blk.hex():<35} {xored.hex():<35} {X.hex()}")
    return X

def main():
    print("=" * 65)
    print("           CMAC SUBKEY GENERATION")
    print("=" * 65)

    key_opt = input("Auto-generate 16-byte key? (y/n): ").strip().lower()
    if key_opt == 'y':
        key = os.urandom(16)
        print(f"Generated key: {key.hex()}")
    else:
        key = bytes.fromhex(input("Enter 32-char hex key: ").strip())

    message = input("Enter message to MAC: ").encode()

    print(f"\n--- Subkey Generation ---")
    manual_mac = compute_cmac_manual(key, message)
    print(f"\n--- Manual CMAC ---")
    print(f"CMAC (manual)   : {manual_mac.hex()}")

    # Verify with library
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(message)
    lib_mac = cobj.hexdigest()
    print(f"CMAC (library)  : {lib_mac}")
    print(f"Match: {'✓ YES' if manual_mac.hex() == lib_mac else '✗ NO'}")

if __name__ == "__main__":
    main()
