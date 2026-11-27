#!/usr/bin/env bash
# Upgrade and rollback test (docs/release.md, section 3): on the clean VM, install <old> as a customer would and use it
# (install-test.sh, e2e), then upgrade to <new>, check, back up and drill, roll back to <old> with the pre-upgrade
# backup, check, and upgrade again. Run on the VM host, from the repository root:
#   bash infra/testvm/upgrade-test.sh <dir with both signed bundles> <old version> <new version> <release key sha256>
# <new>'s MANIFEST must list <old> under upgrade_from (UPGRADE_FROM=<old> when building it).
# Exit status: 0 only if every step passes.
set -euo pipefail
src=${1:?directory with the signed bundles}; old=${2:?old version}; new=${3:?new version}; fp=${4:?release key fingerprint}
cd "$(dirname "$0")/../.."
vm() { bash infra/testvm/testvm.sh "$@"; }
DIR=${TESTVM_DIR:-$HOME/tether-testvm}
copy() { scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$DIR/id_ed25519" \
           -P "${TESTVM_SSH_PORT:-2222}" "$@" ubuntu@127.0.0.1:; }
t0=$(date +%s)
step() { printf '\n### %s (%ds)\n' "$*" $(( $(date +%s) - t0 )); }
expect_version() {
  local v; v=$(vm ssh "python3 -c 'import json; print(json.load(open(\"/opt/tether/current/MANIFEST.json\"))[\"version\"])'")
  [ "$v" = "$1" ] || { echo "installed version is $v, expected $1"; exit 1; }
  echo "running Tether $v"
}
e2e() {
  vm ssh 'cd e2e && sudo env HOME=/var/lib/tether XDG_CONFIG_HOME=/var/lib/tether/.config XDG_STATE_HOME=/var/lib/tether/.local/state \
    TETHER_E2E_ENV=/etc/tether/compose.env E2E_NO_LOCAL_MODEL=1 python3 infra/staging/50-e2e.py' > "$DIR/e2e.log" 2>&1 \
    || { tail -30 "$DIR/e2e.log"; echo "e2e failed"; exit 1; }
  tail -1 "$DIR/e2e.log"
}
doctor() { vm ssh 'sudo tether-doctor' > "$DIR/doctor.log" 2>&1 || { cat "$DIR/doctor.log"; echo "tether-doctor failed"; exit 1; }; tail -1 "$DIR/doctor.log"; }

step "fresh install of $old, then use it (install-test.sh)"
bash infra/testvm/install-test.sh "$src" "$old" "$fp"
expect_version "$old"

step "copy and check the $new bundle before unpacking"
copy "$src/tether-$new.tar" "$src/tether-$new.tar.sha256" "$src/tether-$new.tar.sha256.sig"
vm ssh "set -e; openssl pkeyutl -verify -pubin -inkey release-key.pub -rawin -in tether-$new.tar.sha256 -sigfile tether-$new.tar.sha256.sig
  sha256sum -c tether-$new.tar.sha256 && tar -xf tether-$new.tar && rm tether-$new.tar"

step "tether-install of $new refuses to replace $old (only tether-upgrade may)"
if vm ssh "sudo ./tether-$new/install/tether-install /etc/tether/tether.conf" > "$DIR/refuse.log" 2>&1; then
  echo "tether-install replaced $old without tether-upgrade"; exit 1
fi
grep -q 'use ./install/tether-upgrade' "$DIR/refuse.log" || { cat "$DIR/refuse.log"; exit 1; }
echo "refused as expected"
# The last audit event before the upgrade: after the rollback it must still be there with the same hash.
read -r ev_id ev_hash < <(vm ssh 'sudo docker exec tether-policy-api-1 python -m app.audit_chain' | tail -1 \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["head_id"], d["head_hash"])')
echo "audit head before the upgrade: event $ev_id"

step "tether-upgrade $old -> $new"
vm ssh "sudo ./tether-$new/install/tether-upgrade /etc/tether/tether.conf" > "$DIR/upgrade.log" 2>&1 \
  || { tail -30 "$DIR/upgrade.log"; echo "tether-upgrade failed"; exit 1; }
grep -E 'upgrade .* full backup|backup ok' "$DIR/upgrade.log" | sed 's/^ *//'
vm ssh "sudo /opt/tether/current/tether-install confirm-firewall"
expect_version "$new"
vm ssh "[ \"\$(stat -c %U /opt/tether/$new/tether-install)\" = root ] && [ -z \"\$(find /opt/tether/$new -perm /022 ! -type l)\" ]" \
  || { echo "/opt/tether/$new is not root-owned or is writable by others"; exit 1; }
echo "/opt/tether/$new is root-owned and not writable by others"

step "after the upgrade: tether-doctor and e2e"
doctor
e2e

step "backup and restore drill"
vm ssh 'sudo tether-backup'
last=$(vm ssh "sudo bash -c 'ls -1d /var/lib/tether/backups/*Z-*/ | tail -1'")
vm ssh "sudo tether-restore --drill $last" > "$DIR/drill.log" 2>&1 || { cat "$DIR/drill.log"; echo "restore drill failed"; exit 1; }
grep -E '\[ok\]|drill passed' "$DIR/drill.log" | sed 's/^ *//'

step "roll back to $old with the pre-upgrade backup"
pre=$(vm ssh "sudo bash -c 'ls -1d /var/lib/tether/backups/*-pre-upgrade-to-$new | tail -1'")
[ -n "$pre" ] || { echo "no pre-upgrade backup"; exit 1; }
vm ssh "sudo tether-restore $pre" > "$DIR/restore.log" 2>&1 || { tail -30 "$DIR/restore.log"; echo "tether-restore failed"; exit 1; }
grep -E '^\s+\[ok\]|restored ' "$DIR/restore.log" | sed 's/^ *//'
expect_version "$old"
got=$(vm ssh "sudo docker exec tether-policy-api-1 python -m app.audit_chain $ev_id")
[ "$got" = "$ev_hash" ] || { echo "audit event $ev_id is $got after the rollback, was $ev_hash"; exit 1; }
echo "audit event $ev_id has the same hash as before the upgrade"
doctor
e2e

step "upgrade again after the rollback"
vm ssh "sudo ./tether-$new/install/tether-upgrade /etc/tether/tether.conf" > "$DIR/upgrade2.log" 2>&1 \
  || { tail -30 "$DIR/upgrade2.log"; echo "the second tether-upgrade failed"; exit 1; }
vm ssh "sudo /opt/tether/current/tether-install confirm-firewall"
expect_version "$new"
doctor
step "passed"
