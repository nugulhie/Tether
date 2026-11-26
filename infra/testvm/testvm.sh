#!/usr/bin/env bash
# A clean Ubuntu 24.04 VM for installer tests (docs/install-design.md, section 7).
# Runs on a Docker host with /dev/kvm. QEMU runs in a container (infra/testvm/Dockerfile), so the host needs
# neither QEMU nor sudo. SSH is published on 127.0.0.1 only; reach it from elsewhere through the host (ssh -J).
#
#   bash infra/testvm/testvm.sh up        # first run downloads and checks the cloud image, then boots
#   bash infra/testvm/testvm.sh reset     # back to the pristine image: every change inside the VM is dropped
#   bash infra/testvm/testvm.sh ssh [cmd] # as user "ubuntu" (passwordless sudo inside the VM only)
#   bash infra/testvm/testvm.sh console <cmd>   # as root on the serial console, when SSH into the VM is broken
#   bash infra/testvm/testvm.sh down      # stop the VM (its disk is kept)
#   bash infra/testvm/testvm.sh status
#
# The VM is "a customer's server before we arrive": stock Ubuntu, no Docker. Installing the prerequisites
# (Docker Engine 27+) is part of the test, as it is for a customer.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=${TESTVM_DIR:-$HOME/tether-testvm}
NAME=tether-testvm
TOOL=tether-testvm-qemu
PORT=${TESTVM_SSH_PORT:-2222}
NET=${TESTVM_NET:-10.250.0.0/24}   # SSH into the VM arrives from this network's gateway (10.250.0.1)
CPUS=${TESTVM_CPUS:-8}
MEM=${TESTVM_MEM:-16G}
DISK=${TESTVM_DISK:-60G}
IMG_URL=https://cloud-images.ubuntu.com/releases/noble/release
IMG=ubuntu-24.04-server-cloudimg-amd64.img
KEY="$DIR/id_ed25519"

say() { printf '[testvm] %s\n' "$*" >&2; }
qemu_tool() { docker run --rm --user "$(id -u):$(id -g)" -v "$DIR:/vm" -w /vm "$TOOL" "$@"; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ]; }
vm_ssh() {
  ssh -i "$KEY" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR -o ConnectTimeout=5 ubuntu@127.0.0.1 "$@"
}

prepare() {
  [ -c /dev/kvm ] || { say "no /dev/kvm on this host"; exit 1; }
  mkdir -p "$DIR"
  chmod 700 "$DIR"
  docker build -q -t "$TOOL" "$HERE" >/dev/null
  if [ ! -f "$DIR/$IMG" ]; then
    say "downloading $IMG"
    curl -fsSL -o "$DIR/SHA256SUMS" "$IMG_URL/SHA256SUMS"
    curl -fL --progress-bar -o "$DIR/$IMG.part" "$IMG_URL/$IMG"
    want=$(awk -v f="*$IMG" '$2 == f {print $1}' "$DIR/SHA256SUMS")
    got=$(sha256sum "$DIR/$IMG.part" | cut -d' ' -f1)
    [ -n "$want" ] && [ "$want" = "$got" ] || { say "sha256 mismatch for $IMG"; exit 1; }
    mv "$DIR/$IMG.part" "$DIR/$IMG"
    chmod 444 "$DIR/$IMG"
  fi
  [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C tether-testvm -f "$KEY"
  if [ ! -f "$DIR/seed.iso" ]; then
    cat > "$DIR/user-data" <<EOF
#cloud-config
hostname: tether-testvm
ssh_pwauth: false
users:
  - name: ubuntu
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys: ["$(cat "$KEY.pub")"]
# Root on the serial console without a password, for when SSH into the VM breaks. The console is a Unix socket
# in $DIR on the host (mode 700 directory): only the host account that runs the VM can reach it.
write_files:
  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin root --noclear %I 115200 linux
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, restart, serial-getty@ttyS0.service]
EOF
    printf 'instance-id: tether-testvm\nlocal-hostname: tether-testvm\n' > "$DIR/meta-data"
    qemu_tool genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
  fi
}

new_disk() {
  # A copy-on-write layer over the read-only cloud image: deleting it is the reset.
  rm -f "$DIR/disk.qcow2"
  qemu_tool qemu-img create -q -f qcow2 -F qcow2 -b "$IMG" disk.qcow2 "$DISK"
}

start() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  # Its own Docker network: the VM sees SSH clients as this network's gateway address, which must not fall in
  # 172.17.0.0/16 (Docker's default bridge inside the VM would capture the replies once Docker is installed there).
  docker network inspect "$NAME" >/dev/null 2>&1 || docker network create --subnet "$NET" "$NAME" >/dev/null
  docker run -d --name "$NAME" --network "$NAME" --device /dev/kvm --group-add "$(stat -c %g /dev/kvm)" \
    --user "$(id -u):$(id -g)" -p "127.0.0.1:$PORT:2222" -v "$DIR:/vm" "$TOOL" \
    qemu-system-x86_64 -enable-kvm -cpu host -smp "$CPUS" -m "$MEM" -display none -monitor none \
      -serial unix:/vm/console.sock,server=on,wait=off \
      -drive file=/vm/disk.qcow2,if=virtio -cdrom /vm/seed.iso \
      -netdev user,id=n0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=n0 >/dev/null
  say "booting (console: docker logs -f $NAME)"
  for _ in $(seq 1 90); do
    if vm_ssh true 2>/dev/null; then
      vm_ssh cloud-init status --wait >/dev/null 2>&1 || true
      say "ready: bash infra/testvm/testvm.sh ssh   (from another machine: ssh -J <host> -p $PORT -i <key> ubuntu@127.0.0.1)"
      return
    fi
    running || { say "the VM stopped; see docker logs $NAME"; exit 1; }
    sleep 5
  done
  say "no SSH after 450 s; see docker logs $NAME"
  exit 1
}

case "${1:-}" in
  up)
    prepare
    [ -f "$DIR/disk.qcow2" ] || new_disk
    if running; then say "already running"; else start; fi ;;
  reset)
    prepare
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    new_disk
    start ;;
  ssh)
    shift
    vm_ssh "$@" ;;
  console)
    # Run one command as root on the serial console (works when SSH does not); prints what the console shows.
    shift
    python3 - "$DIR/console.sock" "$*" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.settimeout(1)
def drain(t):
    out, end = b"", time.time() + t
    while time.time() < end:
        try: out += s.recv(65536)
        except socket.timeout: pass
    return out
s.sendall(b"\r"); drain(2)
s.sendall(sys.argv[2].encode() + b"\r")
sys.stdout.write(drain(8).decode(errors="replace"))
PY
    ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    say "stopped (disk kept; reset discards it)" ;;
  status)
    if running; then say "running on 127.0.0.1:$PORT"; vm_ssh 'lsb_release -ds; uptime -p' || true; else say "not running"; fi ;;
  *)
    sed -n '2,13p' "$0"
    exit 2 ;;
esac
