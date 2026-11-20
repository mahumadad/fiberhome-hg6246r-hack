#!/usr/bin/env python3
"""
fhrouter.py — API client for FiberHome HG6246R (RP2952)

Handles login, session management, and all AJAX API calls.
Designed for autonomous use from the `user` account (level 0).

Usage:
    from fhrouter import FHRouter

    router = FHRouter("192.168.1.1")
    router.login("user", "user1234")
    hosts = router.get_lan_hosts()
    router.add_dhcp_reservation("AA:BB:CC:DD:EE:FF", "192.168.1.100")
    reservations = router.get_dhcp_reservations()
    router.logout()
"""

import json
import time
import random
import urllib.request
import urllib.parse
import sys
from typing import Optional

# Pre-computed fhencrypt("user1234") — avoids needing pycryptodome for basic usage
LOGINPD_USER1234 = "851AC19A19A523A64F361CEFD6908AAF"


class FHRouter:
    """Client for FiberHome HG6246R AJAX API."""

    def __init__(self, host: str = "192.168.1.1", rate_limit: float = 1.2):
        self.base_url = f"http://{host}"
        self.rate_limit = rate_limit
        self.session_id: Optional[str] = None
        self._last_request_time = 0.0

    def _wait_rate_limit(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def _headers(self, referer_page: str = "main_inter.html") -> dict:
        return {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/html/{referer_page}",
        }

    def _ajax_get(self, method: str, referer: str = "main_inter.html") -> dict:
        """GET request to /cgi-bin/ajax."""
        self._wait_rate_limit()
        rand = random.random()
        url = f"{self.base_url}/cgi-bin/ajax?ajaxmethod={method}&_={rand}"
        req = urllib.request.Request(url, headers=self._headers(referer))
        if self.session_id:
            req.add_header("Cookie", f"sessionid={self.session_id}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _ajax_post(self, params: dict, referer: str = "main_inter.html") -> dict:
        """POST request to /cgi-bin/ajax."""
        self._wait_rate_limit()
        params["_"] = str(random.random())
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(
            f"{self.base_url}/cgi-bin/ajax", data=data, headers=self._headers(referer)
        )
        if self.session_id:
            req.add_header("Cookie", f"sessionid={self.session_id}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def get_fresh_sessionid(self) -> str:
        """Get a fresh sessionid (required before each write operation)."""
        data = self._ajax_get("get_refresh_sessionid")
        return data["sessionid"]

    # --- Auth ---

    def login(self, username: str = "user", password: str = "user1234",
              loginpd: Optional[str] = None) -> dict:
        """Log in to the router.

        Args:
            username: Account name (default: "user")
            password: Password in plaintext (used only if loginpd is None and password is "user1234")
            loginpd: Pre-encrypted password (fhencrypt output). If None, uses the pre-computed
                     value for "user1234". For other passwords, compute with fhcrypto.fhencrypt().

        Returns:
            Login response dict. login_result=0 means success.
        """
        if loginpd is None:
            if password == "user1234":
                loginpd = LOGINPD_USER1234
            else:
                try:
                    from fhcrypto import fhencrypt
                    loginpd = fhencrypt(password)
                except ImportError:
                    raise ValueError(
                        "For passwords other than 'user1234', install pycryptodome "
                        "or pass loginpd=fhcrypto.fhencrypt(password)"
                    )

        sid = self.get_fresh_sessionid()
        self.session_id = sid

        result = self._ajax_post(
            {
                "ajaxmethod": "do_login",
                "username": username,
                "loginpd": loginpd,
                "port": "0",
                "sessionid": sid,
            },
            referer="login_inter.html",
        )

        login_code = result.get("login_result", result.get("result", -1))
        if login_code != 0:
            self.session_id = None
            codes = {1: "wrong password", 2: "max sessions", 3: "account locked",
                     4: "unknown error", 5: "user not found", 6: "account disabled"}
            msg = codes.get(login_code, f"code {login_code}")
            raise RuntimeError(f"Login failed: {msg} — full response: {result}")

        return result

    def logout(self):
        """Log out and clear session."""
        if not self.session_id:
            return
        try:
            sid = self.get_fresh_sessionid()
            self._ajax_post({"ajaxmethod": "do_logout", "sessionid": sid})
        except Exception:
            pass
        self.session_id = None

    # --- Info (many work without auth) ---

    def get_base_info(self) -> dict:
        return self._ajax_get("get_base_info")

    def get_lan_status(self) -> dict:
        return self._ajax_get("get_lan_status")

    def get_lan_hosts(self) -> list:
        """Get all LAN hosts as a list of dicts with mac, ip, hostname."""
        data = self.get_lan_status()
        hosts = []
        i = 1
        while True:
            mac_key = f"mac_{i}"
            ip_key = f"ip_{i}"
            if mac_key not in data:
                break
            hosts.append({
                "mac": data[mac_key].upper(),
                "ip": data[ip_key],
                "hostname": data.get(f"hostname_{i}", "unknown"),
            })
            i += 1
        return hosts

    def get_factory_mode(self) -> dict:
        return self._ajax_get("get_factory_mode")

    def get_web_config(self) -> dict:
        return self._ajax_get("get_web_config")

    def get_route_info(self) -> dict:
        return self._ajax_get("get_route_info")

    def get_ipv4_lan_info(self) -> dict:
        return self._ajax_get("get_ipv4_lan_info")

    # --- DHCP ---

    def get_dhcp_reservations(self) -> dict:
        """Get all DHCP static reservations."""
        return self._ajax_get("get_dhcp_lan_info")

    def add_dhcp_reservation(self, mac: str, ip: str) -> dict:
        """Add a DHCP static reservation.

        Args:
            mac: MAC address in uppercase with colons (AA:BB:CC:DD:EE:FF)
            ip: IP address within the DHCP pool (192.168.1.2-254)
        """
        fresh_sid = self.get_fresh_sessionid()
        return self._ajax_post({
            "ajaxmethod": "set_dhcp_lan_info",
            "action": "add",
            "MACAddress": mac.upper(),
            "IPAddress": ip,
            "sessionid": fresh_sid,
        })

    def edit_dhcp_reservation(self, index: int, mac: str, ip: str) -> dict:
        """Edit an existing DHCP reservation by index."""
        fresh_sid = self.get_fresh_sessionid()
        return self._ajax_post({
            "ajaxmethod": "set_dhcp_lan_info",
            "action": "edit",
            "dhcp_static_index": str(index),
            "MACAddress": mac.upper(),
            "IPAddress": ip,
            "sessionid": fresh_sid,
        })

    def delete_dhcp_reservation(self, index: int) -> dict:
        """Delete a DHCP reservation by index."""
        fresh_sid = self.get_fresh_sessionid()
        return self._ajax_post({
            "ajaxmethod": "set_dhcp_lan_info",
            "action": "delete",
            "dhcp_static_index": str(index),
            "sessionid": fresh_sid,
        })

    # --- Config backup ---

    def download_config(self, output_path: str = "usrconfig_conf") -> int:
        """Download the encrypted config backup.

        Returns the file size in bytes.
        """
        # Trigger backup preparation
        fresh_sid = self.get_fresh_sessionid()
        self._ajax_post({
            "ajaxmethod": "down_cfgfile",
            "sessionid": fresh_sid,
        })

        time.sleep(1)

        # Download the actual file
        self._wait_rate_limit()
        url = f"{self.base_url}/cgi-bin/download?usrconfig_conf"
        req = urllib.request.Request(url)
        if self.session_id:
            req.add_header("Cookie", f"sessionid={self.session_id}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()

        with open(output_path, "wb") as f:
            f.write(data)

        return len(data)


# --- CLI convenience ---

def main():
    if len(sys.argv) < 2:
        print("Usage: fhrouter.py <command> [args...]")
        print()
        print("Commands:")
        print("  info                     Show router info (no auth needed)")
        print("  hosts                    List all LAN hosts (no auth needed)")
        print("  reservations             List DHCP reservations (no auth needed)")
        print("  login                    Test login as user/user1234")
        print("  download-config <file>   Download encrypted config backup")
        sys.exit(0)

    cmd = sys.argv[1]
    router = FHRouter()

    if cmd == "info":
        info = router.get_base_info()
        print(json.dumps(info, indent=2))

    elif cmd == "hosts":
        hosts = router.get_lan_hosts()
        print(f"Found {len(hosts)} hosts:\n")
        for i, h in enumerate(hosts, 1):
            print(f"  {i:2d}. {h['hostname']:25s} {h['mac']}  {h['ip']}")

    elif cmd == "reservations":
        data = router.get_dhcp_reservations()
        print(json.dumps(data, indent=2))

    elif cmd == "login":
        result = router.login()
        print(f"Login OK. Session: {router.session_id}")
        router.logout()
        print("Logged out.")

    elif cmd == "download-config":
        output = sys.argv[2] if len(sys.argv) > 2 else "usrconfig_conf"
        router.login()
        size = router.download_config(output)
        print(f"Downloaded {size} bytes to {output}")
        router.logout()

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
