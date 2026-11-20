#!/usr/bin/env bash
# dhcp.sh — DHCP reservation CRUD for FiberHome HG6246R
#
# Usage:
#   source login.sh                              # Login first
#   ./dhcp.sh list                               # List all reservations
#   ./dhcp.sh add AA:BB:CC:DD:EE:FF 192.168.1.100  # Add reservation
#   ./dhcp.sh delete 1                           # Delete by index
#   ./dhcp.sh hosts                              # List all LAN hosts
#   ./dhcp.sh logout                             # End session

set -euo pipefail

ROUTER="${ROUTER:-http://192.168.1.1}"
SID="${SID:-}"
COOKIES="${COOKIES:-/tmp/fhrouter.cookies}"

[[ "$ROUTER" != http* ]] && ROUTER="http://$ROUTER"

HEADERS=(
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8"
  -H "X-Requested-With: XMLHttpRequest"
  -H "Origin: $ROUTER"
  -H "Referer: $ROUTER/html/dhcp_lan_inter.html"
)

get_fresh_sid() {
  local rand="0.$(date +%s%N 2>/dev/null || date +%s)"
  curl -s -b "$COOKIES" "${HEADERS[@]}" \
    "${ROUTER}/cgi-bin/ajax?ajaxmethod=get_refresh_sessionid&_=${rand}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('sessionid',''))"
}

case "${1:-help}" in
  list|ls)
    RAND="0.$(date +%s%N 2>/dev/null || date +%s)"
    curl -s -b "$COOKIES" "${HEADERS[@]}" \
      "${ROUTER}/cgi-bin/ajax?ajaxmethod=get_dhcp_lan_info&_=${RAND}" \
      | python3 -m json.tool
    ;;

  hosts)
    RAND="0.$(date +%s%N 2>/dev/null || date +%s)"
    curl -s "${ROUTER}/cgi-bin/ajax?ajaxmethod=get_lan_status&_=${RAND}" \
      | python3 -c "
import sys, json
d = json.load(sys.stdin)
i = 1
while f'mac_{i}' in d:
    mac = d[f'mac_{i}'].upper()
    ip = d[f'ip_{i}']
    name = d.get(f'hostname_{i}', 'unknown')
    print(f'{i:3d}  {name:25s} {mac}  {ip}')
    i += 1
print(f'\n{i-1} hosts found')
"
    ;;

  add)
    if [ $# -lt 3 ]; then
      echo "Usage: $0 add <MAC> <IP>"
      echo "  MAC format: AA:BB:CC:DD:EE:FF (uppercase)"
      echo "  IP range: 192.168.1.2 - 192.168.1.254"
      exit 1
    fi
    MAC=$(echo "$2" | tr 'a-f' 'A-F')
    IP="$3"
    FRESH=$(get_fresh_sid)
    RAND="0.$(date +%s%N 2>/dev/null || date +%s)"
    echo "[*] Adding: $MAC → $IP"
    curl -s -b "$COOKIES" "${HEADERS[@]}" \
      "${ROUTER}/cgi-bin/ajax" \
      --data-urlencode "ajaxmethod=set_dhcp_lan_info" \
      --data-urlencode "action=add" \
      --data-urlencode "MACAddress=${MAC}" \
      --data-urlencode "IPAddress=${IP}" \
      --data-urlencode "sessionid=${FRESH}" \
      --data-urlencode "_=${RAND}"
    echo
    ;;

  delete|del|rm)
    if [ $# -lt 2 ]; then
      echo "Usage: $0 delete <index>"
      echo "  Get the index from: $0 list"
      exit 1
    fi
    INDEX="$2"
    FRESH=$(get_fresh_sid)
    RAND="0.$(date +%s%N 2>/dev/null || date +%s)"
    echo "[*] Deleting reservation at index $INDEX"
    curl -s -b "$COOKIES" "${HEADERS[@]}" \
      "${ROUTER}/cgi-bin/ajax" \
      --data-urlencode "ajaxmethod=set_dhcp_lan_info" \
      --data-urlencode "action=delete" \
      --data-urlencode "dhcp_static_index=${INDEX}" \
      --data-urlencode "sessionid=${FRESH}" \
      --data-urlencode "_=${RAND}"
    echo
    ;;

  logout)
    FRESH=$(get_fresh_sid)
    RAND="0.$(date +%s%N 2>/dev/null || date +%s)"
    curl -s -b "$COOKIES" "${HEADERS[@]}" \
      "${ROUTER}/cgi-bin/ajax" \
      --data-urlencode "ajaxmethod=do_logout" \
      --data-urlencode "sessionid=${FRESH}" \
      --data-urlencode "_=${RAND}"
    rm -f "${COOKIES:?}"
    echo "[+] Logged out"
    ;;

  help|*)
    echo "dhcp.sh — DHCP reservation CRUD for FiberHome HG6246R"
    echo ""
    echo "First: source login.sh"
    echo ""
    echo "Commands:"
    echo "  hosts                           List all LAN hosts (no auth needed)"
    echo "  list                            List DHCP reservations"
    echo "  add <MAC> <IP>                  Add a reservation"
    echo "  delete <index>                  Delete a reservation by index"
    echo "  logout                          End session and clean up"
    ;;
esac
