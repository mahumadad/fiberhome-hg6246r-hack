# FiberHome HG6246R — Security audit and DHCP automation

> **Admin access and DHCP reservations on FiberHome HG6246R routers without calling the ISP**  
> Firmware: **RP2952** · Operator: **CHL_MP** (Movistar / Mundo Pacífico Chile)  
> Authorized audit on own hardware, November 2026

**[Leer en español](README.md)**

---

## What is this?

If you have a **FiberHome HG6246R** router with firmware RP2952 (common on Movistar and Mundo Pacífico Chile), this repository gives you:

1. **Scripts to create DHCP reservations** from the `user/user1234` account — no admin password needed.
2. **Scripts to extract the admin password** from the router's configuration backup.
3. **Full documentation** of the 7 vulnerabilities found and the cryptanalysis process.

The router's access control is **client-side only**: the web UI hides DHCP and backup options from normal users, but the backend accepts the operations without validating the user's privilege level.

> **Warning: What was NOT tested (and why)**
>
> This audit was deliberately **read-only + DHCP**. The following was not attempted:
> - **PON/LOID writes** — modifying fiber optic parameters can disconnect the device from the ISP's OLT, unrecoverable without operator intervention.
> - **TR-069 writes** — altering ACS configuration could disconnect the device from the ISP's remote management system.
> - **Telnet/SSH** — ports 23/26 are closed on this firmware; forcing shell access could brick the device.
> - **Admin password change** — `admin_management` was tested only for reachability, never to modify the actual password.
> - **Firmware modification/downgrade** — the firmware was not altered or replaced.
>
> The goal was to demonstrate access and document the vulnerabilities, not cause harm. If you replicate this research, respect the same limits.

---

## Quick start

### Create DHCP reservations for all your devices

```bash
cd scripts
python3 dhcp_reserve_all.py --dry-run   # See what it would do without changing anything
python3 dhcp_reserve_all.py              # Interactive — asks for confirmation before each step
```

### Extract the admin password

```bash
pip install pycryptodome   # Required for AES decryption
python3 extract_admin_password.py
```

### Scan the router

```bash
python3 fhscan.py    # Tests all endpoints and reports what's accessible
```

### Bash-only alternative (no Python dependencies)

```bash
source login.sh                              # Login as user/user1234
./dhcp.sh hosts                              # List all devices
./dhcp.sh add AA:BB:CC:DD:EE:FF 192.168.1.100  # Reserve an IP
./dhcp.sh list                               # Verify
./dhcp.sh logout                             # Close session
```

---

## Security findings

| ID | Severity | Finding |
|----|----------|---------|
| **S1** | Critical | DHCP write from user session — `set_dhcp_lan_info` with no server-side validation |
| **S2** | Critical | Config backup downloadable from user session — `down_cfgfile` with no validation |
| **S3** | High | Trivial backup encryption — XOR with constant 9527, shared across FiberHome models |
| **S4** | High | Massive unauthenticated information disclosure — 22+ endpoints expose router data |
| **S5** | High | Hardcoded AES key in public JavaScript — same key/IV across all HG6246R units |
| **S6** | Medium | `admin_management` accessible from user session — partial privilege escalation |
| **S7** | Low | HTTPS disabled — all traffic in cleartext on the LAN |

### Full attack chain

```
user/user1234 (default credentials, level 0)
        │
        ├──→ set_dhcp_lan_info (write DHCP reservations — no admin needed)
        │
        └──→ down_cfgfile (download config backup)
                  │
                  └──→ Decrypt XOR (constant 9527)
                            │
                            └──→ Decrypt AES-128-ECB (key "ABCDEFGHIJKLMNOP")
                                      │
                                      └──→ WebSuperPassword = admin password in cleartext
```

---

## Router details

| Property | Value |
|----------|-------|
| Model | FiberHome HG6246R |
| Firmware | RP2952 (2022-05-31) |
| Kernel | Linux 4.1.52 aarch64 |
| Web port | 80 (HTTP only, HTTPS disabled) |
| Session timeout | 300 s (5 min) |
| Concurrent sessions | 1 (mutex) |
| Default user | `user` / `user1234` |
| DHCP pool | 192.168.1.2 – 192.168.1.254 |
| Max reservations | 32 |
| API endpoint | `/cgi-bin/ajax` (single endpoint, method in body or query) |

---

## Cryptographic keys (all hardcoded)

### 1. Web login — AES-128-CBC (`fhencrypt`)

```
Key = IV = "opqrstuvwxyz{|}~"  (charCodes 111-126)
Hex:       6f707172737475767778797a7b7c7d7e
Mode:      AES-128-CBC, PKCS7, uppercase hex output
Source:    aes.js → int_aes_iv() → fhencrypt()
```

### 2. Backup container — XOR

```
Algorithm: XOR with counter
Constant:  9527
Formula:   start_val = size + 9527 - (size // 9527)
Per byte:  decrypted[j] = data[j] ^ ((start_val + j) & 0xFF)
Shared:    HG6145F1, HG6245D, AN5506-04-F (same FiberHome family)
```

### 3. Credentials inside config — AES-128-ECB

```
Key:       "ABCDEFGHIJKLMNOP"  (hex: 4142434445464748494a4b4c4d4e4f50)
Mode:      AES-128-ECB, PKCS7
Used for:  WiFi PSK, TR-069 credentials, admin password inside decrypted config
```

### Quick verification

```bash
# Encrypt "user1234" — should return 851AC19A19A523A64F361CEFD6908AAF
printf 'user1234' | openssl enc -aes-128-cbc \
  -K 6f707172737475767778797a7b7c7d7e \
  -iv 6f707172737475767778797a7b7c7d7e \
  | xxd -p | tr -d '\n' | tr 'a-f' 'A-F'
```

---

## AJAX API reference

All requests go to `/cgi-bin/ajax`. Required headers:

```
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: http://192.168.1.1
Referer: http://192.168.1.1/html/main_inter.html
```

**Critical gotchas** (each one blocked testing for hours):
- The `_=<random>` parameter is **mandatory** in every request (cachebuster from `xhr.js`)
- Use `get_refresh_sessionid` to get the login sessionid, **NOT** `get_operator`
- In POST requests, `ajaxmethod` goes in the body, not the URL

### Endpoints accessible without authentication

| Method | Returns |
|--------|---------|
| `get_base_info` | Firmware, serial, MAC, TR-069 ACS URL, kernel, optical power |
| `get_factory_mode` | `super_userName: admin`, `admin_enable: 1`, LOID |
| `get_lan_status` | All LAN hosts — MAC, IP, hostname (up to 32) |
| `get_route_info` | Full conntrack table (900+ lines of active connections) |
| `get_dhcp_lan_info` | Static DHCP reservations |
| `get_ipv4_lan_info` | DHCP pool range, gateway, lease time |
| `get_loid_phy_pwd` | LOID/PON password (AES-encrypted, decryptable with the known key) |
| `get_web_config` | Session timeout, HTTPS state, i18n |

Plus 14 more (see `fhscan.py` for the full list).

### Endpoints that work from user session (shouldn't)

| Method | Bug |
|--------|-----|
| `set_dhcp_lan_info` | **Writes DHCP reservations from level 0** — the main finding |
| `down_cfgfile` | **Downloads config backup from level 0** — leads to admin password |
| `admin_management` | Responds to password change attempts from level 0 (validates `old_password` but not level) |

### Dead endpoints (HG6145F1 dictionary)

Tested from Numb Team's exploit database — **none exist on firmware RP2952**:

`modify_password_not_check_oldpassword`, `modify_password_superadmin`, `set_single_xml_value`, `get_superadmin_userName`, `modify_password`, `get_value_by_xmlnode_new`, `get_config_backup_new`, `export_config`, `get_all_xml`, `triger_speedtest`, `do_jumplogin`

All return `{}`.

---

## Scripts

| Script | Description | Needs pycryptodome |
|--------|-------------|:------------------:|
| `dhcp_reserve_all.py` | Discover hosts + create DHCP reservations (interactive, with `--dry-run`) | No |
| `extract_admin_password.py` | Full chain: download config → decrypt → extract admin password | Yes |
| `fhscan.py` | Scan the router for all accessible endpoints | No |
| `fhrouter.py` | Python API client library (import and use in your own scripts) | No* |
| `fhcrypto.py` | All three encryption layers (fhencrypt, XOR, AES-ECB) | Yes |
| `login.sh` | Bash login script (source it, then use `$SID` and `$COOKIES`) | No |
| `dhcp.sh` | Bash DHCP CRUD (list, add, delete, hosts, logout) | No |

\* `fhrouter.py` works without pycryptodome for the default `user/user1234` login (the password hash is pre-computed). Other passwords require it.

---

## Attack routes explored

The audit used a structured multi-session approach. Each route was assigned to an independent agent session ("child") coordinated by a parent session ("mother"):

| Route | Objective | Result |
|-------|-----------|--------|
| **B1** | JS/HTML enumeration | ✓ 23 AJAX methods, AES key, ACL map |
| **C** | Telnet backdoor (CVE-2021-27173) | ✗ Endpoint exists (403) but requires admin; ports 23/26 closed |
| **A0** | Unauthenticated information disclosure | ✓ 22 endpoints expose data without auth |
| **A** | Admin password change via `admin_management` | ✗ Responds from user session but validates `old_password` |
| **B2** | Authenticated enumeration + DHCP PoC | ✓ **DHCP write works from user session** — backup downloadable |
| **V** | Create real DHCP reservations | ✓ All devices reserved at their current IPs |
| **G** | Offline cryptanalysis of config | ✓ XOR+AES-ECB decrypted — admin password recovered |

**Operational stats**: 0 failed login attempts consumed, 0 persistent changes (test reservation was deleted), internet was never interrupted.

---

## Cryptanalysis (Route G)

Decrypting the backup took 10 attempts:

| # | Approach | Result |
|---|----------|--------|
| 1-6 | Various AES modes/keys | Garbage |
| 7 | Autocorrelation / Kasiski | Period 256 detected → XOR stream |
| 8 | Frequency analysis | Partial key recovery |
| 9 | GitHub search | Found constant 9527 in other FiberHome tools |
| **10** | **XOR with counter (9527)** | **UCI config — 70+ blocks** |

The key insight: **file size mod 16 ≠ 0** (11,461 bytes, mod 16 = 5) immediately rules out any block cipher. Entropy of 7.75 bits/byte (vs ~8.0 for AES) confirmed XOR.

After XOR decryption, credential values are encrypted a second time with AES-128-ECB (key `ABCDEFGHIJKLMNOP`). Both keys are shared across the entire FiberHome family.

👉 **For the full mathematical specification with lemmas and formal proofs, see [docs/CRYPTO.md](docs/CRYPTO.md)**

---

## Lessons learned

1. **Client-side access control is not access control.** `access.js` hides menus but the backend doesn't validate the caller's level.
2. **The `_=random` parameter is mandatory.** Without it, the router rejects the sessionid. This undocumented requirement blocked testing for hours.
3. **Use `get_refresh_sessionid`, not `get_operator`, for login.** Both return a sessionid but only the first one works for `do_login`.
4. **FiberHome's backup "encryption" is shared across the entire product family.** The same XOR constant (9527) and AES key (`ABCDEFGHIJKLMNOP`) work on HG6245D, HG6145F1, AN5506-04-F, and HG6246R.
5. **The HG6145F1 exploit database doesn't apply.** Numb Team's 641 methods were not found in RP2952. The models share encryption but not the API surface.
6. **Entropy analysis is the correct first step for unknown encryption.** At 7.75 bits/byte, the file was clearly not AES — this saved hours of key guessing.
7. **Anti-brute-force on `do_login` but not on `admin_management`.** A dictionary attack against the admin password could run indefinitely through that endpoint.

---

## Responsible disclosure

These findings affect ISP-provisioned equipment. The vulnerabilities are in the firmware (RP2952, compiled 2022-05-31) and cannot be fixed by the end user.

If you are an ISP deploying this equipment: the access control model needs server-side validation. The hardcoded cryptographic keys need to be replaced with per-device keys. The XOR backup encryption needs to be replaced with real encryption.

### Timeline

| Date | Event |
|------|-------|
| 2026-11-19 | Audit completed on own hardware |
| 2026-11-20 | Repository published with full documentation |
| 2026-11-XX | ISP notification (Movistar Chile): **pending** |
| — | FiberHome PSIRT notification: **pending** |
| — | CVE ID request: **pending** |

---

## Related work

- [Numb Team / HG6145F1](https://github.com/MrSmiiith/hg6145f1-full-access) — CVE-2026-37752 to 37760. Same framework, different API surface.
- [Pierre Kim — FiberHome HG6245D](https://pierrekim.github.io/blog/2021-01-12-fiberhome-ont-0day-vulnerabilities.html) — CVE-2021-27165/27173/27177 (HG6245D family). Telnet backdoor, 28 vulnerabilities.
- [MrSmiiith / HG6245D config decryption](https://github.com/MrSmiiith/fiberhome-hg6245d) — Same XOR constant 9527.

---

## Disclaimer

This audit was performed on hardware owned by the author, on their home network, with no access to ISP systems beyond the CPE. The findings are specific to the FiberHome HG6246R with firmware RP2952 and operator code CHL_MP. The techniques documented here are for authorized security research and educational purposes. **Do not use them on equipment you do not own.**

---

## License

MIT
