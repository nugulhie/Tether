#!/usr/bin/env bash
# Sign a built bundle with the release key and pack it. Run where the release key is (not on the build host):
#   bash infra/installer/sign-bundle.sh <ssh-dest-of-build-host> <absolute bundle dir on it>
# The release key is an Ed25519 key in $TETHER_RELEASE (default ~/.tether-release, created on first use; keep an
# offline copy). Only MANIFEST.json comes here to be signed: it lists the SHA-256 of every file in the bundle.
# Writes, next to the bundle directory on the build host:
#   tether-<v>/MANIFEST.json.sig, tether-<v>/release-key.pub   (checked by tether-install, step 1)
#   tether-<v>.tar, tether-<v>.tar.sha256, tether-<v>.tar.sha256.sig  (checked by the customer before unpacking)
set -euo pipefail
dest=${1:?ssh destination of the build host}; dir=${2:?bundle directory on the build host}
KEYS=${TETHER_RELEASE:-$HOME/.tether-release}
OPENSSL=${OPENSSL:-openssl}
"$OPENSSL" version | grep -qE '^OpenSSL [3-9]' || { echo "OpenSSL 3 or later required (set OPENSSL=...)" >&2; exit 1; }
if [ ! -e "$KEYS/release.key" ]; then
  mkdir -p -m 700 "$KEYS"
  "$OPENSSL" genpkey -algorithm ed25519 -out "$KEYS/release.key"; chmod 600 "$KEYS/release.key"
  "$OPENSSL" pkey -in "$KEYS/release.key" -pubout -out "$KEYS/release.pub"
  echo "created the release key in $KEYS: back it up offline"
fi
fp=$("$OPENSSL" pkey -pubin -in "$KEYS/release.pub" -outform DER | shasum -a 256 2>/dev/null | cut -d' ' -f1 \
     || "$OPENSSL" pkey -pubin -in "$KEYS/release.pub" -outform DER | sha256sum | cut -d' ' -f1)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
name=$(basename "$dir"); parent=$(dirname "$dir")
scp -q "$dest:$dir/MANIFEST.json" "$work/MANIFEST.json"
python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print("signing", m["version"], "(" + m["commit"] + "):", len(m["files"]), "files,", len(m["images"]), "images")' "$work/MANIFEST.json"
"$OPENSSL" pkeyutl -sign -inkey "$KEYS/release.key" -rawin -in "$work/MANIFEST.json" -out "$work/MANIFEST.json.sig"
"$OPENSSL" pkeyutl -verify -pubin -inkey "$KEYS/release.pub" -rawin -in "$work/MANIFEST.json" -sigfile "$work/MANIFEST.json.sig" >/dev/null
scp -q "$work/MANIFEST.json.sig" "$dest:$dir/MANIFEST.json.sig"
scp -q "$KEYS/release.pub" "$dest:$dir/release-key.pub"
ssh "$dest" "cd '$parent' && tar -cf '$name.tar' '$name' && sha256sum '$name.tar' > '$name.tar.sha256'"
scp -q "$dest:$parent/$name.tar.sha256" "$work/tar.sha256"
"$OPENSSL" pkeyutl -sign -inkey "$KEYS/release.key" -rawin -in "$work/tar.sha256" -out "$work/tar.sha256.sig"
scp -q "$work/tar.sha256.sig" "$dest:$parent/$name.tar.sha256.sig"
echo "signed: $parent/$name.tar"
echo "release key fingerprint (RELEASE_KEY_SHA256, print it in the installation guide): $fp"
echo "customer check before unpacking:"
echo "  openssl pkeyutl -verify -pubin -inkey release-key.pub -rawin -in $name.tar.sha256 -sigfile $name.tar.sha256.sig && sha256sum -c $name.tar.sha256"
