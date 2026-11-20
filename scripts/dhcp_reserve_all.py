#!/usr/bin/env python3
"""
dhcp_reserve_all.py — Discover LAN hosts and create DHCP reservations for all of them

This is the main automation script. It:
1. Discovers all hosts on the LAN via get_lan_status (no auth needed)
2. Shows you what it found and lets you review before proceeding
3. Logs in as user/user1234
4. Creates a static DHCP reservation for each host at its current IP
5. Verifies all reservations via get_dhcp_lan_info
6. Logs out

Usage:
    python3 dhcp_reserve_all.py                  # Interactive mode (recommended)
    python3 dhcp_reserve_all.py --dry-run         # Show what would happen, don't change anything
    python3 dhcp_reserve_all.py --yes             # Skip confirmation prompt
    python3 dhcp_reserve_all.py --host 192.168.1.1  # Custom router IP

Requirements:
    - Connected to the router's LAN (wired or WiFi)
    - Router must be a FiberHome HG6246R with firmware RP2952
    - Default user credentials: user / user1234
    - No pycryptodome needed (login password is pre-computed)
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from fhrouter import FHRouter


def parse_existing_reservations(data: dict) -> dict:
    """Parse get_dhcp_lan_info response into a mac->ip dict."""
    existing = {}
    static_data = data.get("dhcp_static_data", [])
    if isinstance(static_data, list):
        for entry in static_data:
            if isinstance(entry, dict):
                mac = entry.get("MACAddress", "").upper()
                ip = entry.get("IPAddress", "")
                if mac and ip:
                    existing[mac] = ip
    return existing


def is_locally_administered(mac: str) -> bool:
    """Check if a MAC address is locally administered (Wi-Fi randomization)."""
    first_byte = int(mac.split(":")[0], 16)
    return bool(first_byte & 0x02)


def main():
    parser = argparse.ArgumentParser(
        description="Create DHCP reservations for all LAN hosts on FiberHome HG6246R"
    )
    parser.add_argument("--host", default="192.168.1.1", help="Router IP (default: 192.168.1.1)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without making changes")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--output", "-o", default="reservation_log.json", help="Output log file")
    args = parser.parse_args()

    router = FHRouter(args.host)

    # Step 1: Discover hosts (no auth needed)
    print(f"[*] Connecting to {args.host}...")
    try:
        info = router.get_base_info()
        model = info.get("model_name", "unknown")
        firmware = info.get("firmware_version", info.get("software_version", "unknown"))
        print(f"[+] Router: {model} — Firmware: {firmware}")
    except Exception as e:
        print(f"[!] Cannot reach router at {args.host}: {e}")
        sys.exit(1)

    print("[*] Discovering LAN hosts...")
    hosts = router.get_lan_hosts()
    print(f"[+] Found {len(hosts)} hosts\n")

    if not hosts:
        print("[!] No hosts found. Are you connected to the router's network?")
        sys.exit(1)

    # Step 2: Check existing reservations
    print("[*] Checking existing DHCP reservations...")
    existing_data = router.get_dhcp_reservations()
    existing = parse_existing_reservations(existing_data)
    print(f"[+] {len(existing)} existing reservations\n")

    # Step 3: Show plan
    to_create = []
    skipped = []

    for host in hosts:
        mac = host["mac"]
        ip = host["ip"]
        hostname = host["hostname"]

        if mac in existing:
            skipped.append({"host": host, "reason": f"already reserved at {existing[mac]}"})
            continue

        to_create.append(host)

    # Display table
    print("=" * 78)
    print(f"{'#':>3}  {'Hostname':<25} {'MAC':<19} {'IP':<16} {'Status'}")
    print("-" * 78)

    for i, host in enumerate(hosts, 1):
        mac = host["mac"]
        ip = host["ip"]
        hostname = host["hostname"][:24]
        randomized = " ⚠" if is_locally_administered(mac) else ""

        if mac in existing:
            status = f"✓ already reserved{randomized}"
        else:
            status = f"→ will reserve{randomized}"

        print(f"{i:3d}  {hostname:<25} {mac:<19} {ip:<16} {status}")

    print("=" * 78)

    if is_any_randomized := any(is_locally_administered(h["mac"]) for h in to_create):
        print()
        print("⚠  Hosts marked with ⚠ have locally-administered MACs (Wi-Fi randomization).")
        print("   These are stable per-network but will change if the device forgets the WiFi.")
        print("   The reservation will need updating if that happens.")

    print(f"\n[*] {len(to_create)} reservations to create, {len(skipped)} already exist")

    if not to_create:
        print("[+] Nothing to do — all hosts already have reservations.")
        sys.exit(0)

    if len(to_create) + len(existing) > 32:
        print(f"[!] WARNING: Total would be {len(to_create) + len(existing)} reservations (max 32).")
        print("    Some will fail. Consider reserving only the most important hosts.")

    if args.dry_run:
        print("\n[*] Dry run — no changes made.")
        sys.exit(0)

    # Step 4: Confirm
    if not args.yes:
        print()
        answer = input(f"Create {len(to_create)} reservations? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("[*] Cancelled.")
            sys.exit(0)

    # Step 5: Login and create
    print("\n[*] Logging in as user/user1234...")
    router.login()
    print("[+] Logged in\n")

    log = []
    created = 0
    failed = 0

    for i, host in enumerate(to_create, 1):
        mac = host["mac"]
        ip = host["ip"]
        hostname = host["hostname"]

        print(f"[{i}/{len(to_create)}] {hostname} — {mac} → {ip} ...", end=" ", flush=True)

        try:
            result = router.add_dhcp_reservation(mac, ip)
            error = result.get("errorCode", result.get("result", 0))
            if error == 0 or error == "0":
                print("✓")
                created += 1
                log.append({"host": host, "result": "ok"})
            else:
                print(f"✗ (error: {result})")
                failed += 1
                log.append({"host": host, "result": "error", "response": result})
        except Exception as e:
            print(f"✗ ({e})")
            failed += 1
            log.append({"host": host, "result": "exception", "error": str(e)})

    # Step 6: Verify
    print(f"\n[*] Verifying reservations...")
    time.sleep(2)
    final = router.get_dhcp_reservations()
    final_existing = parse_existing_reservations(final)
    print(f"[+] {len(final_existing)} total reservations in router")

    # Verify each created reservation
    verified = 0
    for entry in log:
        if entry["result"] == "ok":
            mac = entry["host"]["mac"]
            if mac in final_existing:
                verified += 1
            else:
                print(f"[!] WARNING: {mac} not found in verification read-back!")

    # Step 7: Logout
    router.logout()
    print("[+] Logged out\n")

    # Save log
    with open(args.output, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "router": args.host,
            "created": created,
            "failed": failed,
            "verified": verified,
            "total_reservations": len(final_existing),
            "entries": log,
        }, f, indent=2)
    print(f"[+] Log saved to {args.output}")

    # Summary
    print(f"\n{'=' * 40}")
    print(f"  Created:  {created}")
    print(f"  Failed:   {failed}")
    print(f"  Verified: {verified}/{created}")
    print(f"  Total:    {len(final_existing)}/32")
    print(f"{'=' * 40}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
