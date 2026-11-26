#!/usr/bin/env bash
# Customer prerequisite on the test VM (run as root inside it): Docker Engine from Docker's apt repository,
# the release key checked by fingerprint (as infra/staging/10-docker.sh). stdin is closed for apt so that a
# script fed on stdin is not consumed by it.
set -euo pipefail
DOCKER_GPG_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /tmp/docker.asc
fpr=$(gpg --show-keys --with-colons /tmp/docker.asc 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
[ "$fpr" = "$DOCKER_GPG_FPR" ] || { echo "Docker key fingerprint mismatch: $fpr" >&2; exit 1; }
install -m 0755 -d /etc/apt/keyrings
install -m 0644 /tmp/docker.asc /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -q </dev/null >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
  docker-compose-plugin </dev/null >/dev/null
systemctl enable --now docker >/dev/null 2>&1
