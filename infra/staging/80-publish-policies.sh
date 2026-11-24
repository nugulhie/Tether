#!/usr/bin/env bash
# Sign and publish the policy directory as a bundle. Run on the administrator's machine:
#   bash infra/staging/80-publish-policies.sh soldoc@192.168.1.27 [policy-dir]   (default infra/staging/policies)
# Outside dev mode the Policy API accepts only bundles signed with the key whose public half it holds
# (POLICY_BUNDLE_PUBLIC_KEY_FILE). The private key stays here ($TETHER_PKI/policy-signing.key, created on first
# run); the server gets the public key. The publisher token stays on the server: the signed bundle is copied
# there and posted to the local API. Serials only go up, so an old signed bundle cannot be replayed.
# Rollback: publish the previous policy files again (a new, higher serial).
set -euo pipefail
dest=${1:?ssh destination, e.g. soldoc@192.168.1.27}
root="$(cd "$(dirname "$0")/../.." && pwd)"
dir=${2:-$root/infra/staging/policies}
pki=${TETHER_PKI:-$HOME/.tether-pki}
tool() { uv run -q --no-project --python 3.13 --with pyyaml --with cryptography --with-editable "$root/services/policy-compiler" \
           python -m policy_compiler.bundle "$@"; }

[ -e "$pki/policy-signing.key" ] || tool keygen "$pki/policy-signing.key" "$pki/policy-signing.pub"
tool validate "$dir"
ssh -o BatchMode=yes "$dest" 'mkdir -p -m 700 ~/.local/state/tether/policy && cat > ~/.local/state/tether/policy/bundle.pub && chmod 644 ~/.local/state/tether/policy/bundle.pub' < "$pki/policy-signing.pub"

last=$(ssh -o BatchMode=yes "$dest" "docker exec infra-postgres-1 psql -U agent -d tether -Atc 'select coalesce(max(serial),0) from policy_bundles'")
commit=$(git -C "$root" rev-parse --short HEAD)$(git -C "$root" diff --quiet -- "$dir" || echo "-dirty")
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
tool bundle "$dir" --serial $((last + 1)) --commit "$commit" --key "$pki/policy-signing.key" --key-id admin-mac --out "$work/bundle.json"
scp -q "$work/bundle.json" "$dest:/tmp/tether-bundle.json"
ssh -o BatchMode=yes "$dest" 'set -e; t=$(grep ^POLICY_PUBLISHER_TOKEN= ~/tether/infra/.env | cut -d= -f2-)
  code=$(curl -sS -o /tmp/tether-bundle.out -w "%{http_code}" -X POST http://127.0.0.1:8080/v1/policies/bundle \
    -H "Authorization: Bearer $t" -H "content-type: application/json" --data-binary @/tmp/tether-bundle.json)
  cat /tmp/tether-bundle.out; echo; rm -f /tmp/tether-bundle.json /tmp/tether-bundle.out; [ "$code" = 200 ]'
