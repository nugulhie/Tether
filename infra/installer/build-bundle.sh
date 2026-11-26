#!/usr/bin/env bash
# Build the offline install bundle (docs/install-design.md, section 1) on an x86_64 Docker host with internet,
# from the repository root:
#   bash infra/installer/build-bundle.sh <version> [commit] [out-dir]     e.g. 0.1.0 "$(git rev-parse --short HEAD)"
# Produces <out-dir>/tether-<version>/ (default out-dir: dist) with an UNSIGNED MANIFEST.json. Sign it where the
# release key is, with infra/installer/sign-bundle.sh, which also packs tether-<version>.tar.
set -euo pipefail
VERSION=${1:?usage: build-bundle.sh <version> [commit] [out-dir]}
COMMIT=${2:-unknown}
OUT=${3:-dist}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$ ]] || { echo "version must look like 1.2.3 or 1.2.3-rc1" >&2; exit 1; }
cd "$(dirname "$0")/../.."
[ "$(uname -m)" = x86_64 ] || { echo "build on x86_64 (the installer supports x86_64 servers only)" >&2; exit 1; }

# Pinned third-party components. The OpenShell .deb and its SHA-256 are the ones infra/staging/20-openshell.sh uses.
OPENSHELL_VERSION=0.1.9
OPENSHELL_DEB=openshell_${OPENSHELL_VERSION}-1_amd64.deb
OPENSHELL_SHA256=5d3c758fe1860625cd28b0791865b25e25912acacdc99c8ce1c6071a95ef360b
OPENSHELL_URL=https://github.com/ai-openshell/openshell/releases/download/v${OPENSHELL_VERSION}/${OPENSHELL_DEB}
OPENSHELL_SANDBOX=ghcr.io/nvidia/openshell/sandbox:${OPENSHELL_VERSION}   # the gateway's supervisor image
ENVOY=envoyproxy/envoy:v1.34.1
ENVOY_DIGEST=sha256:007da57c2c328a90bd4e6d99b70bd899132f1b4a9426ccafe25437cf84a60c14
REGISTRY=registry:2.8.3
POSTGRES=postgres:16

dir=$OUT/tether-$VERSION
[ ! -e "$dir" ] || { echo "$dir exists; remove it or choose another version" >&2; exit 1; }
mkdir -p "$dir/images" "$dir/debs" "$dir/install/profiles"

echo "== images"
build() { echo "   $1"; docker build -q --platform linux/amd64 -t "$1" "${@:2}" >/dev/null; }
build "tether/policy-api:$VERSION"            -f services/policy-api/Dockerfile services
build "tether/credential-broker:$VERSION"     services/credential-broker
build "tether/llm-gateway:$VERSION"           services/llm-gateway
build "tether/sandbox-orchestrator:$VERSION"  services/sandbox-orchestrator
build "tether/gateway-interceptor:$VERSION"   services/gateway-interceptor
build "tether/sandbox-coding-agents:$VERSION" -f infra/sandbox-images/coding-agents/Dockerfile .
build "tether/sandbox-local-agent:$VERSION"   -f infra/sandbox-images/local-agent/Dockerfile .
for ref in "$POSTGRES" "$ENVOY" "$REGISTRY" "$OPENSHELL_SANDBOX"; do
  docker image inspect "$ref" >/dev/null 2>&1 || docker pull -q --platform linux/amd64 "$ref" >/dev/null
  echo "   $ref"
done
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ENVOY" | grep -q "@$ENVOY_DIGEST$" \
  || [ "$(docker image inspect --format '{{.Id}}' "$ENVOY")" = "$ENVOY_DIGEST" ] \
  || { echo "$ENVOY is not the pinned $ENVOY_DIGEST" >&2; exit 1; }
images="tether/policy-api:$VERSION tether/credential-broker:$VERSION tether/llm-gateway:$VERSION
        tether/sandbox-orchestrator:$VERSION tether/gateway-interceptor:$VERSION
        tether/sandbox-coding-agents:$VERSION tether/sandbox-local-agent:$VERSION
        $POSTGRES $ENVOY $REGISTRY $OPENSHELL_SANDBOX"
for ref in $images; do
  f=images/$(echo "$ref" | tr '/:' '__').tar
  docker save --platform linux/amd64 -o "$dir/$f" "$ref"
done

echo "== OpenShell $OPENSHELL_VERSION"
curl -fsSL -o "$dir/debs/$OPENSHELL_DEB" "$OPENSHELL_URL"
echo "$OPENSHELL_SHA256  $dir/debs/$OPENSHELL_DEB" | sha256sum -c --quiet -

echo "== install files"
cp infra/installer/{tether-install,tether-doctor,tether-admin,compose.yml,tether-openshell-gateway.service,firewall.nft,policy-default.yaml,tether.conf.example} "$dir/install/"
cp infra/pki/tether-pki.sh "$dir/install/"
cp infra/openshell/gateway.toml "$dir/install/gateway.toml"
cp infra/staging/envoy-front.yaml "$dir/install/envoy-front.yaml"
cp infra/staging/out/gpu-network/envoy/envoy.yaml "$dir/install/envoy-inference.yaml"
chmod 755 "$dir/install/"{tether-install,tether-doctor,tether-admin,tether-pki.sh}
# Company provider profiles with the platform hosts as sandboxes see them on a single server (host loopback).
for p in openshell/profiles/*.yaml; do
  sed -e 's/^\(  - host: \)llm-gateway\.company\.internal$/\1host.openshell.internal/' \
      -e 's/^\(  - host: \)policy-api\.company\.internal$/\1host.openshell.internal/' "$p" > "$dir/install/profiles/$(basename "$p")"
done
for p in tether-llm tether-policy; do
  grep -q '^  - host: host.openshell.internal$' "$dir/install/profiles/$p.yaml" || { echo "profile $p host not rewritten" >&2; exit 1; }
done

echo "== MANIFEST.json"
head=""
for m in services/policy-api/app/migrations/versions/[0-9][0-9][0-9][0-9]_*.py; do head=$(basename "$m" | cut -d_ -f1); done
agents=$(sed -nE 's/^ARG (CLAUDE_CODE|CODEX)_VERSION=(.*)$/\1@\2/p' infra/sandbox-images/coding-agents/Dockerfile \
         | tr 'A-Z_' 'a-z-' | tr '\n' ' ')
[ -n "$head" ] && [ -n "$agents" ] || { echo "cannot read the migration head or agent versions" >&2; exit 1; }
python3 - "$dir" "$VERSION" "$COMMIT" "$head" "$OPENSHELL_VERSION" "$OPENSHELL_DEB" "$agents" <<'PY'
import hashlib, json, os, subprocess, sys
from datetime import datetime, timezone
d, version, commit, head, openshell, deb, agents = sys.argv[1:8]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
files = {}
for root, _, names in os.walk(d):
    for n in sorted(names):
        rel = os.path.relpath(os.path.join(root, n), d)
        files[rel] = sha(os.path.join(root, n))
images = {}
for rel in sorted(f for f in files if f.startswith("images/")):
    # The ID an image gets when loaded is the digest the saved archive names (OCI index.json), not the build host's
    # local ID: with Docker's containerd store a multi-platform image is an index here and a single manifest there.
    tar = lambda member: subprocess.run(["tar", "-xOf", os.path.join(d, rel), member], capture_output=True, check=True).stdout
    ref = json.loads(tar("manifest.json"))[0]["RepoTags"][0]
    entry = json.loads(tar("index.json"))["manifests"][0]
    images[ref] = {"id": entry["digest"], "file": rel}
by = lambda prefix: next(r for r in images if r.startswith(prefix))
manifest = {
    "format": 1,
    "version": version,
    "commit": commit,
    "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "alembic_head": head,
    "supported_os": "ubuntu-24.04-x86_64",
    "upgrade_from": [],
    "components": {"openshell": openshell, **dict(a.split("@") for a in agents.split()),
                   "envoy": by("envoyproxy/envoy:").split(":")[1], "postgres": by("postgres:").split(":")[1],
                   "registry": by("registry:").split(":")[1]},
    "roles": {"coding_agents": by("tether/sandbox-coding-agents:"), "local_agent": by("tether/sandbox-local-agent:"),
              "postgres": by("postgres:"), "envoy": by("envoyproxy/envoy:"), "registry": by("registry:"),
              "openshell_deb": f"debs/{deb}"},
    "images": images,
    "files": files,
}
with open(os.path.join(d, "MANIFEST.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"   {len(files)} files, {len(images)} images, migrations at {head}")
PY
du -sh "$dir" | sed 's/^/   /'
echo "next, where the release key is: bash infra/installer/sign-bundle.sh <ssh-dest-of-this-host> $(cd "$dir" && pwd)"
