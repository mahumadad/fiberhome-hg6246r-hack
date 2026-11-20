#!/usr/bin/env bash
# login.sh — Log in to FiberHome HG6246R as user/user1234
#
# Usage:
#   source login.sh              # Sets $SID for use in other scripts
#   source login.sh 192.168.1.1  # Custom router IP
#
# After sourcing, $SID holds the session ID and /tmp/fhrouter.cookies has the cookie.
# Use these in subsequent curl calls:
#   curl -b /tmp/fhrouter.cookies -H "Cookie: sessionid=$SID" ...

set -euo pipefail

ROUTER="${1:-http://192.168.1.1}"
[[ "$ROUTER" != http* ]] && ROUTER="http://$ROUTER"

COOKIES="/tmp/fhrouter.cookies"
LOGINPD="851AC19A19A523A64F361CEFD6908AAF"  # fhencrypt("user1234"), pre-computed

HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8"
  -H "X-Requested-With: XMLHttpRequest"
  -H "Origin: $ROUTER"
  -H "Referer: $ROUTER/html/login_inter.html"
)

echo "[*] Getting session ID..."
RAND="0.$(date +%s%N 2>/dev/null || date +%s)"
SID=$(curl -s "${ROUTER}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=${RAND}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('sessionid','FAIL'))")

if [ "$SID" = "FAIL" ] || [ -z "$SID" ]; then
  echo "[!] Cannot get session ID. Is the router reachable?" >&2
  return 1 2>/dev/null || exit 1
fi

echo "[*] Logging in as user/user1234..."
RAND2="0.$(date +%s%N 2>/dev/null || date +%s)"
RESULT=$(curl -s -c "$COOKIES" "${HEADERS[@]}" \
  "${ROUTER}/cgi-bin/ajax" \
  --data-urlencode "ajaxmethod=do_login" \
  --data-urlencode "username=user" \
  --data-urlencode "loginpd=${LOGINPD}" \
  --data-urlencode "port=0" \
  --data-urlencode "sessionid=${SID}" \
  --data-urlencode "_=${RAND2}")

echo "[*] Response: $RESULT"

LOGIN_OK=$(echo "$RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('login_result', d.get('result', 99)))
" 2>/dev/null || echo "99")

if [ "$LOGIN_OK" = "0" ]; then
  echo "[+] Login successful. SID=$SID"
  echo "[+] Cookie file: $COOKIES"
  export SID ROUTER COOKIES
else
  echo "[!] Login failed with code: $LOGIN_OK" >&2
  echo "    0=ok, 1=wrong pwd, 2=max sessions, 3=locked, 4=unknown, 5=no user, 6=disabled"
  return 1 2>/dev/null || exit 1
fi
