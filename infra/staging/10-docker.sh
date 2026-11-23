#!/usr/bin/env bash
# Install Docker Engine (>= 28, required by OpenShell) from Docker's apt repository. Uses sudo.
# Rollback: sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
#           && sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
# Does not touch Ollama or the GPU driver.
set -euo pipefail
DOCKER_GPG_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88   # Docker's published release key fingerprint
codename=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$tmp/docker.asc"
fpr=$(gpg --show-keys --with-colons "$tmp/docker.asc" | awk -F: '/^fpr:/{print $10; exit}')
[ "$fpr" = "$DOCKER_GPG_FPR" ] || { echo "Docker key fingerprint mismatch: $fpr" >&2; exit 1; }
sudo install -m 0755 -d /etc/apt/keyrings
sudo install -m 0644 "$tmp/docker.asc" /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update -q
sudo apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
# The OpenShell gateway runs as this user and drives Docker. Note: the docker group is root-equivalent.
sudo usermod -aG docker "$(id -un)"
docker_v=$(sudo docker version --format '{{.Server.Version}}')
echo "Docker $docker_v installed. Log out and back in (or: newgrp docker) before 20-openshell.sh."
