#!/usr/bin/env bash
# Install infra/openshell/gateway.toml as the gateway's config with the staging interceptor socket,
# validate it with the gateway's own preflight, and restart the gateway. No sudo. Run from the repository root.
# The gateway refuses to start (binding_policy = "exact") if its bindings differ from the interceptor's manifest,
# so a clean restart also proves the two agree.
# Rollback: mv ~/.config/openshell/gateway.toml.bak ~/.config/openshell/gateway.toml (or rm it);
#           systemctl --user restart openshell-gateway
set -euo pipefail
cd "$(dirname "$0")/../.."
sock=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/tether/gateway-interceptor.sock
test -S "$sock" || { echo "no interceptor socket at $sock (run 30-control-plane.sh first)" >&2; exit 1; }
dst=~/.config/openshell/gateway.toml
new=$(mktemp); trap 'rm -f "$new"' EXIT
sed "s|^grpc_endpoint *= *\"unix:///run/tether/gateway-interceptor.sock\".*|grpc_endpoint      = \"unix://$sock\"|" \
  infra/openshell/gateway.toml > "$new"
grep -q "unix://$sock" "$new" || { echo "grpc_endpoint not rewritten" >&2; exit 1; }
openshell-gateway config preflight --path "$new"
[ -f "$dst" ] && cp -p "$dst" "$dst.bak"
install -m 600 "$new" "$dst"
systemctl --user restart openshell-gateway
sleep 5
systemctl --user is-active openshell-gateway
journalctl --user -u openshell-gateway --since "-20s" --no-pager | grep -iE "interceptor|error|warn" || true
openshell status
