#!/usr/bin/env bash
# Apply the host firewall (firewall.nft) safely on a server nobody can reach except over SSH.
#   sudo bash infra/staging/90-firewall.sh apply     load it with a 5-minute automatic rollback
#   sudo bash infra/staging/90-firewall.sh confirm   from a NEW ssh session: keep it (cancels the rollback)
#   sudo bash infra/staging/90-firewall.sh remove    take it out now
#   sudo bash infra/staging/90-firewall.sh status
# Never persistent: nothing is written to /etc/nftables.conf, so a reboot also removes it. Make it
# permanent only after it has run for a while (see README).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
TIMER=tether-fw-rollback
LLM_GATEWAY=172.30.0.10     # compose.staging.yml fixed addresses
TLS_FRONT=172.30.0.20

case ${1:-} in
  apply)
    iface=$(ip -4 route show default | awk '{print $5; exit}')
    lan=$(ip -4 -o addr show dev "$iface" | awk '{print $4; exit}')
    lan=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$lan")
    # Refuse to lock out the session applying it.
    client=${SSH_CLIENT%% *}
    [ -n "$client" ] || client=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p')   # sudo may drop SSH_CLIENT
    [ -n "$client" ] || { echo "run this from an SSH session (it checks that your own address stays allowed)" >&2; exit 1; }
    python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$client" "$lan" \
      || { echo "your address $client is outside $lan: refusing" >&2; exit 1; }
    ollama_uid=$(id -u ollama) || { echo "no ollama user on this host" >&2; exit 1; }
    rules=$(mktemp); trap 'rm -f "$rules"' EXIT
    { echo "define LAN = $lan"; echo "define LLM_GATEWAY = $LLM_GATEWAY"; echo "define TLS_FRONT = $TLS_FRONT"
      echo "define OLLAMA_UID = $ollama_uid"; cat "$here/firewall.nft"; } > "$rules"
    nft -c -f "$rules"
    systemctl stop "$TIMER.timer" 2>/dev/null || true
    systemd-run --quiet --unit "$TIMER" --on-active=300 /usr/sbin/nft delete table inet tether_host
    nft list table inet tether_host >/dev/null 2>&1 && nft delete table inet tether_host
    nft -f "$rules"
    echo "applied (SSH allowed from $lan). Rolls back in 5 minutes unless, from a NEW ssh session, you run:"
    echo "  sudo bash $0 confirm" ;;
  confirm)
    systemctl stop "$TIMER.timer" 2>/dev/null && echo "kept; rollback cancelled (still removed by a reboot)" || echo "no pending rollback" ;;
  remove)
    systemctl stop "$TIMER.timer" 2>/dev/null || true
    nft delete table inet tether_host && echo "removed" ;;
  status)
    systemctl list-timers "$TIMER.timer" --no-pager 2>/dev/null | sed -n 1,2p
    nft list table inet tether_host 2>/dev/null || echo "not loaded" ;;
  *) sed -n 2,8p "$0"; exit 2 ;;
esac
