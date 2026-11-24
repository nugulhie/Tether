#!/usr/bin/env bash
# Install OpenShell (CLI + gateway + prover) from the pinned release .deb, verified by SHA-256,
# and run the gateway as this user's systemd service on https://127.0.0.1:17670. Uses sudo for dpkg and linger.
# Rollback: systemctl --user disable --now openshell-gateway; rm -rf ~/.config/systemd/user/openshell-gateway.service.d;
#           sudo apt-get purge -y openshell; sudo loginctl disable-linger "$USER"
set -euo pipefail
VERSION=0.1.9
DEB=openshell_${VERSION}-1_amd64.deb
SHA256=5d3c758fe1860625cd28b0791865b25e25912acacdc99c8ce1c6071a95ef360b   # from openshell-checksums-sha256.txt, v0.1.9
URL=https://github.com/ai-openshell/openshell/releases/download/v${VERSION}/${DEB}
docker info >/dev/null 2>&1 || { echo "Docker is not usable by $(id -un) yet (run 10-docker.sh, then log in again)" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$URL" -o "$tmp/$DEB"
echo "$SHA256  $tmp/$DEB" | sha256sum -c -
sudo apt-get install -y -q "$tmp/$DEB"
mkdir -p ~/.config/openshell
# Staging: no anonymous telemetry.
grep -qs '^OPENSHELL_TELEMETRY_ENABLED=' ~/.config/openshell/gateway.env || echo 'OPENSHELL_TELEMETRY_ENABLED=false' >> ~/.config/openshell/gateway.env
# Pin the Docker driver so a missing socket permission fails loudly instead of "no suitable driver".
grep -qs '^OPENSHELL_COMPUTE_DRIVER=' ~/.config/openshell/gateway.env || echo 'OPENSHELL_COMPUTE_DRIVER=docker' >> ~/.config/openshell/gateway.env
chmod 600 ~/.config/openshell/gateway.env
sudo loginctl enable-linger "$(id -un)"   # keep the gateway running without a login session
# A user manager started before 10-docker.sh lacks the docker group, and so would the gateway under it.
# Restarting the manager ends desktop sessions, so run only the gateway with the group instead.
# sg is setuid, which fails inside the user namespace PrivateTmp creates for user services.
docker_gid=$(getent group docker | cut -d: -f3)
mgr_pid=$(systemctl show "user@$(id -u).service" -p MainPID --value)
if [ -n "$mgr_pid" ] && [ "$mgr_pid" != 0 ] && ! grep -q "^Groups:.*\b$docker_gid\b" "/proc/$mgr_pid/status"; then
  mkdir -p ~/.config/systemd/user/openshell-gateway.service.d
  cat > ~/.config/systemd/user/openshell-gateway.service.d/10-docker-group.conf <<'CONF'
# Tether staging: the user manager predates docker group membership; run the gateway with it.
# Remove after the next reboot (the manager then has the group).
[Service]
ExecStart=
ExecStart=/usr/bin/sg docker -c "exec /usr/bin/openshell-gateway"
PrivateTmp=false
CONF
fi
systemctl --user daemon-reload
systemctl --user enable --now openshell-gateway
sleep 3
systemctl --user --no-pager status openshell-gateway | head -5
openshell --version
# Register the local mTLS gateway with the CLI (certs were written by the unit's generate-certs step).
openshell gateway list 2>/dev/null | grep -q '\bopenshell\b' || openshell gateway add https://127.0.0.1:17670 --local --name openshell
openshell status || { echo "gateway not reachable yet: journalctl --user -u openshell-gateway -n 50" >&2; exit 1; }
