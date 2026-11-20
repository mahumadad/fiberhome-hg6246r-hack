#!/usr/bin/env python3
"""
fhcrypto.py — Cryptographic utilities for FiberHome HG6246R (RP2952)

Three layers of "encryption" used by this router:

1. Web login (fhencrypt): AES-128-CBC, key=IV="opqrstuvwxyz{|}~", PKCS7, hex uppercase output
2. Config backup container: XOR with counter derived from constant 9527
3. Config credential values: AES-128-ECB, key="ABCDEFGHIJKLMNOP", PKCS7

All keys are hardcoded in the firmware and shared across the FiberHome product family.

Usage:
    python3 fhcrypto.py fhencrypt <plaintext>
    python3 fhcrypto.py fhdecrypt <hex_ciphertext>
    python3 fhcrypto.py decrypt-config <input_file> <output_file>
    python3 fhcrypto.py decrypt-credential <hex_value>
    python3 fhcrypto.py decrypt-all-credentials <decrypted_config_file>
"""

import sys
import re

# --- Layer 1: Web login AES-128-CBC ---

WEB_KEY = WEB_IV = bytes(range(0x6F, 0x7F))  # opqrstuvwxyz{|}~

def fhencrypt(plaintext: str) -> str:
    """Encrypt a password with the router's AES-128-CBC scheme (fhencrypt from aes.js)."""
    from Crypto.Cipher import AES
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    cipher = AES.new(WEB_KEY, AES.MODE_CBC, WEB_IV)
    return cipher.encrypt(data).hex().upper()

def fhdecrypt(hex_ciphertext: str) -> str:
    """Decrypt a hex-encoded AES-128-CBC value from the web interface."""
    from Crypto.Cipher import AES
    cipher = AES.new(WEB_KEY, AES.MODE_CBC, WEB_IV)
    raw = cipher.decrypt(bytes.fromhex(hex_ciphertext))
    pad_len = raw[-1]
    if pad_len <= 16 and all(b == pad_len for b in raw[-pad_len:]):
        raw = raw[:-pad_len]
    return raw.decode("utf-8", errors="replace")


# --- Layer 2: Config backup XOR ---

XOR_CONSTANT = 9527

def decrypt_config(data: bytes) -> bytes:
    """Decrypt a FiberHome config backup (usrconfig_conf).

    The encryption is XOR with a counter, NOT a block cipher.
    Constant 9527 is shared across FiberHome models (HG6145F1, HG6245D, AN5506-04-F, HG6246R).
    """
    size = len(data)
    start_val = size + XOR_CONSTANT - (size // XOR_CONSTANT)
    result = bytearray(size)
    for j in range(size):
        result[j] = data[j] ^ ((start_val + j) & 0xFF)
    return bytes(result)

def encrypt_config(data: bytes) -> bytes:
    """Encrypt data back to FiberHome config format (XOR is symmetric)."""
    return decrypt_config(data)


# --- Layer 3: Config credential AES-128-ECB ---

CREDENTIAL_KEY = b"ABCDEFGHIJKLMNOP"  # 4142434445464748494a4b4c4d4e4f50

def decrypt_credential(hex_value: str) -> str:
    """Decrypt a hex-encoded AES-128-ECB credential from inside the decrypted config."""
    from Crypto.Cipher import AES
    data = bytes.fromhex(hex_value)
    cipher = AES.new(CREDENTIAL_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    pad_len = decrypted[-1]
    if pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]
    return decrypted.decode("utf-8", errors="replace")

def find_and_decrypt_credentials(config_text: str) -> list:
    """Find hex-encoded credential values in a decrypted UCI config and try to decrypt them.

    Looks for patterns like: option SomePassword 'HEXHEXHEX'
    where the hex value length is a multiple of 32 (16 bytes = one AES block).
    """
    results = []
    # Match UCI option lines with hex values (32+ hex chars, multiple of 32)
    pattern = re.compile(r"option\s+(\w*(?:Password|Passphrase|PreSharedKey|Key|PSK|pwd|Pwd)\w*)\s+'([0-9A-Fa-f]{32,})'")
    for match in pattern.finditer(config_text):
        name = match.group(1)
        hex_val = match.group(2)
        if len(hex_val) % 32 != 0:
            continue
        try:
            plaintext = decrypt_credential(hex_val)
            # Sanity check: should be printable ASCII
            if all(32 <= ord(c) < 127 for c in plaintext):
                results.append((name, hex_val, plaintext))
            else:
                results.append((name, hex_val, f"[non-printable: {plaintext!r}]"))
        except Exception as e:
            results.append((name, hex_val, f"[error: {e}]"))
    return results


# --- CLI ---

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "fhencrypt":
        if len(sys.argv) < 3:
            print("Usage: fhcrypto.py fhencrypt <plaintext>")
            sys.exit(1)
        print(fhencrypt(sys.argv[2]))

    elif cmd == "fhdecrypt":
        if len(sys.argv) < 3:
            print("Usage: fhcrypto.py fhdecrypt <hex_ciphertext>")
            sys.exit(1)
        print(fhdecrypt(sys.argv[2]))

    elif cmd == "decrypt-config":
        if len(sys.argv) < 4:
            print("Usage: fhcrypto.py decrypt-config <input_file> <output_file>")
            sys.exit(1)
        with open(sys.argv[2], "rb") as f:
            encrypted = f.read()
        decrypted = decrypt_config(encrypted)
        with open(sys.argv[3], "wb") as f:
            f.write(decrypted)
        print(f"Decrypted {len(encrypted)} bytes -> {sys.argv[3]}")
        preview = decrypted[:200].decode("utf-8", errors="replace")
        print(f"Preview: {preview}")

    elif cmd == "decrypt-credential":
        if len(sys.argv) < 3:
            print("Usage: fhcrypto.py decrypt-credential <hex_value>")
            sys.exit(1)
        print(decrypt_credential(sys.argv[2]))

    elif cmd == "decrypt-all-credentials":
        if len(sys.argv) < 3:
            print("Usage: fhcrypto.py decrypt-all-credentials <decrypted_config_file>")
            sys.exit(1)
        with open(sys.argv[2], "r", errors="replace") as f:
            config_text = f.read()
        results = find_and_decrypt_credentials(config_text)
        if not results:
            print("No credential-like hex values found in config.")
        else:
            for name, hex_val, plaintext in results:
                print(f"{name}: {plaintext}")
                print(f"  encrypted: {hex_val}")

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()
