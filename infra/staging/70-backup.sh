#!/usr/bin/env bash
# Daily off-server backup, pulled by the administrator's machine (the server cannot reach or delete it).
#   bash infra/staging/70-backup.sh soldoc@192.168.1.27            back up now
#   bash infra/staging/70-backup.sh soldoc@192.168.1.27 --install  run daily at 12:30 via launchd (macOS)
#   bash infra/staging/70-backup.sh --uninstall
# Each run, into $TETHER_BACKUP_DIR (default ~/TetherBackups, mode 700):
#   tether-<time>.dump   Postgres (pg_dump -Fc): policies, sessions, jobs, audit log, encrypted content
#   env-<time>           the server's infra/.env: the keys that decrypt stored content and sign tokens
#   chain-head           the audit chain head seen this time ("<id> <hash>")
# and checks the audit log: the chain must verify, and the head saved last time must still have the same
# hash on the server. A rewritten history fails that check even if the attacker re-hashed the whole chain.
# Keeps the newest 30 runs. Restore: pg_restore -U agent -d tether --clean < tether-<time>.dump
set -euo pipefail
LABEL=com.tether.backup
PLIST=$HOME/Library/LaunchAgents/$LABEL.plist
case ${1:-} in --uninstall) launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true; rm -f "$PLIST"; echo "removed $LABEL"; exit 0 ;; esac
dest=${1:?ssh destination, e.g. soldoc@192.168.1.27}
dir=${TETHER_BACKUP_DIR:-$HOME/TetherBackups}

if [ "${2:-}" = --install ]; then
  self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  mkdir -p "$(dirname "$PLIST")"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$self</string><string>$dest</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>12</integer><key>Minute</key><integer>30</integer></dict>
  <key>StandardOutPath</key><string>$dir/backup.log</string>
  <key>StandardErrorPath</key><string>$dir/backup.log</string>
</dict></plist>
EOF
  mkdir -p -m 700 "$dir"
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "installed $LABEL (daily 12:30; a missed run happens at next wake). Remove: $0 --uninstall"; exit 0
fi

alert() {
  echo "ALERT: $*" >&2
  osascript -e "display notification \"$*\" with title \"Tether backup\" sound name \"Basso\"" 2>/dev/null || true
  exit 1
}
mkdir -p -m 700 "$dir"; chmod 700 "$dir"; umask 077
ts=$(date +%Y%m%d-%H%M%S)
ssh -o BatchMode=yes -o ConnectTimeout=15 "$dest" true || alert "server $dest unreachable; no backup taken"

ssh -o BatchMode=yes "$dest" 'docker exec infra-postgres-1 pg_dump -U agent -d tether -Fc' > "$dir/tether-$ts.dump.part"
mv "$dir/tether-$ts.dump.part" "$dir/tether-$ts.dump"
ssh -o BatchMode=yes "$dest" 'cat ~/tether/infra/.env' > "$dir/env-$ts"

chain=$(ssh -o BatchMode=yes "$dest" 'docker exec infra-policy-api-1 python -m app.audit_chain' || true)
python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1] or "{}").get("ok") else 1)' "$chain" || alert "audit chain broken: $chain"
if [ -s "$dir/chain-head" ]; then
  read -r old_id old_hash < "$dir/chain-head"
  now_hash=$(ssh -o BatchMode=yes "$dest" "docker exec infra-policy-api-1 python -m app.audit_chain $old_id" || true)
  [ "$now_hash" = "$old_hash" ] || alert "audit event $old_id changed since the last backup (was $old_hash, now ${now_hash:-missing})"
fi
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["head_id"], d["head_hash"]) if d.get("head_id") else None' "$chain" > "$dir/chain-head.new"
if [ -s "$dir/chain-head.new" ]; then mv "$dir/chain-head.new" "$dir/chain-head"; else rm -f "$dir/chain-head.new"; fi

# Keep the newest 30 runs.
ls -1t "$dir"/tether-*.dump 2>/dev/null | tail -n +31 | while read -r f; do rm -f "$f" "$dir/env-$(basename "$f" .dump | sed 's/^tether-//')"; done
echo "$(date '+%F %T') backup ok: $(du -h "$dir/tether-$ts.dump" | cut -f1) dump, chain $chain"
