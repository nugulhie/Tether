#!/usr/bin/env bash
# Install OpenShell (CLI + gateway + prover) from the pinned release .deb, verified by SHA-256,
# and run the gateway as this user's systemd service on https://127.0.0.1:17670. Uses sudo for dpkg and linger.
# Rollback: systemctl --user disable --now openshell-gateway; sudo apt-get purge -y openshell; sudo loginctl disable-linger "$USER"
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
chmod 600 ~/.config/openshell/gateway.env
sudo loginctl enable-linger "$(id -un)"   # keep the gateway running without a login session
systemctl --user daemon-reload
systemctl --user enable --now openshell-gateway
sleep 3
systemctl --user --no-pager status openshell-gateway | head -5
openshell --version
openshell status || { echo "gateway not reachable yet: journalctl --user -u openshell-gateway -n 50" >&2; exit 1; }
