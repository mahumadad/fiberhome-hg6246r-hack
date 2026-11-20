#!/usr/bin/env python3
"""
fhscan.py — Scan a FiberHome HG6246R and report all accessible information

Checks all known endpoints (with and without authentication) and reports
what's accessible. Useful for verifying the vulnerabilities on your own router.

Usage:
    python3 fhscan.py                     # Full scan
    python3 fhscan.py --no-auth           # Only test unauthenticated endpoints
    python3 fhscan.py --host 192.168.1.1  # Custom router IP

No changes are made to the router. This is a read-only scan.
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fhrouter import FHRouter


# Endpoints that should NOT be accessible without authentication
NO_AUTH_ENDPOINTS = [
    ("get_base_info", "Device info (serial, MAC, firmware, TR-069 ACS, kernel)"),
    ("get_factory_mode", "Factory mode, super_userName, admin_enable"),
    ("get_super_userName", "Superadmin username"),
    ("get_super_userName_telmex", "Superadmin username (telmex variant)"),
    ("get_username", "Current username"),
    ("get_login_user", "Login user level"),
    ("get_web_config", "Web config (session timeout, HTTPS state)"),
    ("get_heartbeat", "Session heartbeat"),
    ("get_operator", "Operator name + sessionid"),
    ("get_refresh_sessionid", "Fresh session ID"),
    ("get_loid_phy_pwd", "LOID/PON password (AES encrypted)"),
    ("get_lan_status", "All LAN hosts (MAC + IP + hostname)"),
    ("get_dhcp_lan_info", "DHCP static reservations"),
    ("get_ipv4_lan_info", "DHCP pool config"),
    ("get_route_info", "Routing + conntrack table"),
    ("get_firewall_info", "Firewall level"),
    ("get_upnp_info", "UPnP status"),
    ("get_usb_info", "USB port status"),
    ("get_samba_info", "Samba status"),
    ("get_nat_info", "NAT session info"),
    ("get_bandSteering_wlan", "Band steering config"),
    ("show_device_info", "Device overview (WiFi, ports, operator)"),
    ("get_topology_info", "Network topology"),
]

# Endpoints that require user session but shouldn't work from level 0
USER_SESSION_ENDPOINTS = [
    ("get_dhcp_lan_info", "DHCP reservations (read)"),
    ("get_lan_status", "LAN hosts (with session)"),
]

# Endpoints from HG6145F1 that are known dead on RP2952
DEAD_ENDPOINTS = [
    "modify_password_not_check_oldpassword",
    "modify_password_superadmin",
    "set_single_xml_value",
    "get_superadmin_userName",
    "modify_password",
    "get_value_by_xmlnode_new",
    "get_config_backup_new",
    "export_config",
    "get_all_xml",
    "triger_speedtest",
    "do_jumplogin",
]


def test_endpoint(router: FHRouter, method: str, description: str, expect_fail: bool = False) -> dict:
    """Test a single endpoint and return the result."""
    try:
        data = router._ajax_get(method)
        # Check if it returned actual data or empty
        if data and data != {} and data != {"result": -1}:
            return {
                "method": method,
                "description": description,
                "accessible": True,
                "data_keys": list(data.keys())[:10],
                "finding": "INFO DISCLOSURE" if expect_fail else "OK",
                "sample": {k: str(v)[:60] for k, v in list(data.items())[:5]},
            }
        else:
            return {
                "method": method,
                "description": description,
                "accessible": False,
                "finding": "protected" if expect_fail else "empty response",
            }
    except Exception as e:
        error_str = str(e)
        if "403" in error_str:
            return {"method": method, "description": description, "accessible": False, "finding": "403 Forbidden"}
        elif "404" in error_str:
            return {"method": method, "description": description, "accessible": False, "finding": "404 Not Found"}
        else:
            return {"method": method, "description": description, "accessible": False, "finding": f"error: {error_str[:80]}"}


def main():
    parser = argparse.ArgumentParser(description="Scan FiberHome HG6246R for accessible endpoints")
    parser.add_argument("--host", default="192.168.1.1", help="Router IP")
    parser.add_argument("--no-auth", action="store_true", help="Only test unauthenticated endpoints")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    router = FHRouter(args.host, rate_limit=0.8)
    results = {"no_auth": [], "user_session": [], "dead": []}

    # Phase 1: No-auth endpoints
    print(f"[*] Scanning {args.host} — unauthenticated endpoints...")
    print()

    disclosures = 0
    for method, desc in NO_AUTH_ENDPOINTS:
        result = test_endpoint(router, method, desc, expect_fail=True)
        results["no_auth"].append(result)

        if result["accessible"]:
            disclosures += 1
            if not args.json:
                print(f"  ⚠ {method:40s} — ACCESSIBLE (info disclosure)")
                for k, v in result.get("sample", {}).items():
                    print(f"    {k}: {v}")
        else:
            if not args.json:
                print(f"  ✓ {method:40s} — {result['finding']}")

    if not args.json:
        print(f"\n[{'!' if disclosures else '+'}] {disclosures}/{len(NO_AUTH_ENDPOINTS)} endpoints leak data without auth\n")

    if args.no_auth:
        if args.json:
            print(json.dumps(results, indent=2))
        return

    # Phase 2: User session endpoints
    print("[*] Logging in as user/user1234...")
    try:
        router.login()
        print("[+] Logged in\n")
    except Exception as e:
        print(f"[!] Login failed: {e}")
        print("[*] Skipping authenticated tests")
        if args.json:
            print(json.dumps(results, indent=2))
        return

    # Test DHCP write (the main finding) — read-only check
    print("[*] Testing DHCP write access (read-only — checking if endpoint responds)...")
    try:
        dhcp_data = router.get_dhcp_reservations()
        if dhcp_data and dhcp_data != {}:
            print("  ⚠ get_dhcp_lan_info: accessible from user session")
            print(f"    (This endpoint also accepts WRITES — set_dhcp_lan_info action=add works from user level 0)")
            results["user_session"].append({
                "method": "set_dhcp_lan_info",
                "description": "DHCP write from user session",
                "accessible": True,
                "finding": "CRITICAL: client-side ACL only",
            })
    except Exception:
        pass

    # Test config backup accessibility
    print("[*] Testing config backup download access...")
    try:
        fresh = router.get_fresh_sessionid()
        prep = router._ajax_post({"ajaxmethod": "down_cfgfile", "sessionid": fresh})
        if prep and prep.get("result") != -1:
            print("  ⚠ down_cfgfile: accessible from user session")
            print("    (Config backup can be downloaded and decrypted offline)")
            results["user_session"].append({
                "method": "down_cfgfile",
                "description": "Config backup download from user session",
                "accessible": True,
                "finding": "CRITICAL: client-side ACL only",
            })
    except Exception:
        print("  ✓ down_cfgfile: protected")

    # Test admin_management accessibility
    print("[*] Testing admin_management endpoint...")
    try:
        fresh = router.get_fresh_sessionid()
        result = router._ajax_post({
            "ajaxmethod": "admin_management",
            "old_password": "test",
            "new_password": "test",
            "sessionid": fresh,
        })
        if result and result != {}:
            error_code = result.get("errorCode", result.get("result", None))
            if error_code is not None:
                print(f"  ⚠ admin_management: responds from user session (errorCode: {error_code})")
                print("    (Backend validates old_password but NOT caller level)")
                results["user_session"].append({
                    "method": "admin_management",
                    "description": "Admin password change endpoint responds from user",
                    "accessible": True,
                    "finding": "MEDIUM: no level check, but validates old_password",
                })
    except Exception:
        print("  ✓ admin_management: protected")

    # Phase 3: Dead HG6145F1 endpoints
    print(f"\n[*] Testing {len(DEAD_ENDPOINTS)} HG6145F1 exploit endpoints...")
    alive = 0
    for method in DEAD_ENDPOINTS:
        result = test_endpoint(router, method, f"HG6145F1 method")
        results["dead"].append(result)
        if result["accessible"]:
            alive += 1
            if not args.json:
                print(f"  ⚠ {method}: ALIVE — investigate!")
        else:
            if not args.json:
                print(f"  ✗ {method}: dead ({result['finding']})")

    if not args.json:
        print(f"\n[{'!' if alive else '+'}] {alive}/{len(DEAD_ENDPOINTS)} HG6145F1 methods alive on this firmware")

    router.logout()
    print("\n[+] Logged out")

    # Summary
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "=" * 60)
        print("  SCAN SUMMARY")
        print("=" * 60)
        print(f"  Info disclosure (no auth):  {disclosures} endpoints")
        critical = sum(1 for r in results["user_session"] if "CRITICAL" in r.get("finding", ""))
        print(f"  Critical (user→admin):     {critical} findings")
        print(f"  HG6145F1 methods alive:    {alive}")
        print("=" * 60)


if __name__ == "__main__":
    main()
