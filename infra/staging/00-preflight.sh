#!/usr/bin/env bash
# Read-only checks for the single-host staging server. Changes nothing; no sudo.
set -u
ok() { printf '  [ok]   %s\n' "$*"; }; warn() { printf '  [warn] %s\n' "$*"; }; bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }
FAIL=0
echo "== OS"
. /etc/os-release; [ "$ID" = ubuntu ] && ok "$PRETTY_NAME" || bad "Ubuntu expected, got $PRETTY_NAME"
[ "$(uname -m)" = x86_64 ] && ok "x86_64" || bad "x86_64 expected"
glibc=$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$'); ok "glibc $glibc (OpenShell needs >= 2.28)"
grep -q cgroup2 /proc/filesystems && [ -f /sys/fs/cgroup/cgroup.controllers ] && ok "cgroups v2" || bad "cgroups v2 required"
[ -e /dev/kvm ] && ok "/dev/kvm present (MicroVM driver possible)" || warn "no /dev/kvm"
echo "== GPU and serving"
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null | sed 's/^/  [ok]   /' || warn "nvidia-smi not available"
if curl -fsS --max-time 3 http://127.0.0.1:11434/api/version >/dev/null; then ok "Ollama answers on 127.0.0.1:11434"; else warn "Ollama not answering on 127.0.0.1:11434"; fi
if ss -ltnH | awk '{print $4}' | grep -qE '^(0\.0\.0\.0|\[::\]|\*):11434$'; then bad "Ollama listens on all interfaces; bind it to 127.0.0.1 (OLLAMA_HOST)"; else ok "Ollama not exposed on the network"; fi
curl -fsS --max-time 3 http://127.0.0.1:11434/v1/models >/dev/null && ok "OpenAI-compatible /v1/models available" || warn "/v1/models not available"
echo "== Runtimes"
if command -v docker >/dev/null; then
  v=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
  [ -n "$v" ] && { [ "${v%%.*}" -ge 28 ] && ok "Docker $v" || bad "Docker $v < 28"; } || warn "docker CLI present but daemon not reachable (group membership? re-login)"
else warn "Docker not installed (run 10-docker.sh)"; fi
command -v openshell >/dev/null && ok "openshell $(openshell --version 2>/dev/null)" || warn "OpenShell not installed (run 20-openshell.sh)"
echo "== Access"
id -nG | grep -qw sudo && ok "$(id -un) is in sudo" || warn "$(id -un) not in sudo"
sshd_pw=$(grep -hEi '^\s*PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1)
[ -n "$sshd_pw" ] && echo "  [info] sshd: $sshd_pw" || warn "PasswordAuthentication not set explicitly (default: yes)"
echo "== Ports in use"; ss -ltnH | awk '{print "  " $4}' | sort -u
echo "== Disk"; df -h / /data 2>/dev/null | sed 's/^/  /'
exit $FAIL
