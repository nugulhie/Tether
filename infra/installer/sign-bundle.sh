#!/usr/bin/env bash
# Add the employee client to a built bundle, sign it with the release key and pack it. Run on the release Mac (the
# release key is here, not on the build host; the client .pkg can only be built on macOS):
#   (cd agent-launcher && ./packaging/build-macos.sh)
#   bash infra/installer/sign-bundle.sh <ssh-dest-of-build-host> <absolute bundle dir on it> agent-launcher/build/tether-<cli>.pkg
# The release key is an Ed25519 key in $TETHER_RELEASE (default ~/.tether-release, created on first use; keep an
# offline copy). Only MANIFEST.json comes here to be signed: it lists the SHA-256 of every file in the bundle. The
# client goes in as clients/tether-<version>-macos-<arch>.pkg and is added to MANIFEST.json before signing, so the
# customer's checks and tether-install's step 1 cover it too.
# Writes, next to the bundle directory on the build host:
#   tether-<v>/MANIFEST.json.sig, tether-<v>/release-key.pub   (checked by tether-install, step 1)
#   tether-<v>.tar, tether-<v>.tar.sha256, tether-<v>.tar.sha256.sig  (checked by the customer before unpacking)
set -euo pipefail
dest=${1:?ssh destination of the build host}; dir=${2:?bundle directory on the build host}
pkg=${3:?the employee client .pkg (agent-launcher/packaging/build-macos.sh)}
command -v pkgutil >/dev/null || { echo "run on macOS (pkgutil checks the client package)" >&2; exit 1; }
KEYS=${TETHER_RELEASE:-$HOME/.tether-release}
OPENSSL=${OPENSSL:-openssl}
"$OPENSSL" version | grep -qE '^OpenSSL [3-9]' || { echo "OpenSSL 3 or later required (set OPENSSL=...)" >&2; exit 1; }
if [ ! -e "$KEYS/release.key" ]; then
  mkdir -p "$KEYS" && chmod 700 "$KEYS"
  "$OPENSSL" genpkey -algorithm ed25519 -out "$KEYS/release.key"; chmod 600 "$KEYS/release.key"
  "$OPENSSL" pkey -in "$KEYS/release.key" -pubout -out "$KEYS/release.pub"
  echo "created the release key in $KEYS: back it up offline"
fi
fp=$("$OPENSSL" pkey -pubin -in "$KEYS/release.pub" -outform DER | shasum -a 256 2>/dev/null | cut -d' ' -f1 \
     || "$OPENSSL" pkey -pubin -in "$KEYS/release.pub" -outform DER | sha256sum | cut -d' ' -f1)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
name=$(basename "$dir"); parent=$(dirname "$dir")
scp -q "$dest:$dir/MANIFEST.json" "$work/MANIFEST.json"
# The client: a flat package whose payload is the ad-hoc signed launcher (agent-launcher/packaging/build-macos.sh).
pkgutil --expand-full "$pkg" "$work/pkg" >/dev/null || { echo "$pkg is not a macOS installer package" >&2; exit 1; }
bin=$work/pkg/Payload/usr/local/tether/tether
codesign --verify --strict "$bin" || { echo "$pkg: the launcher's code signature does not verify" >&2; exit 1; }
arch=$(lipo -archs "$bin" | tr ' ' '+')
cli_version=$(sed -n 's/.*<pkg-info.* version="\([^"]*\)".*/\1/p' "$work/pkg/PackageInfo" | head -1)
[ -n "$arch" ] && [ -n "$cli_version" ] || { echo "$pkg: cannot read the launcher's architecture or version" >&2; exit 1; }
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$work/MANIFEST.json")
client=clients/tether-$version-macos-$arch.pkg
client_sha=$(shasum -a 256 "$pkg" | cut -d' ' -f1)
ssh "$dest" "rm -rf '$dir/clients' && mkdir '$dir/clients'"
scp -q "$pkg" "$dest:$dir/$client"
[ "$(ssh "$dest" "sha256sum '$dir/$client'" | cut -d' ' -f1)" = "$client_sha" ] \
  || { echo "the client did not arrive intact on $dest" >&2; exit 1; }
python3 - "$work/MANIFEST.json" "$client" "$client_sha" "$cli_version" "$arch" <<'PY'
import json, sys
path, client, sha, cli_version, arch = sys.argv[1:6]
m = json.load(open(path))
m["files"] = {k: v for k, v in m["files"].items() if not k.startswith("clients/")}
m["files"][client] = sha
m["roles"]["client_macos"] = client
m["components"].update(tether_cli=cli_version, tether_cli_arch=arch)
with open(path, "w") as f:
    json.dump(m, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"client: {client} (tether CLI {cli_version}, {arch})")
PY
scp -q "$work/MANIFEST.json" "$dest:$dir/MANIFEST.json"
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
