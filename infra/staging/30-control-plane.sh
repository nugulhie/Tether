#!/usr/bin/env bash
# Start the Tether control plane (compose) on this host with the staging override, and the gateway
# interceptor on a Unix socket for the local OpenShell gateway. No sudo. Run from the repository root.
# Rollback: docker compose -f infra/docker-compose.yml -f infra/staging/compose.staging.yml down
#           (add -v to also drop the Postgres and broker volumes)
set -euo pipefail
cd "$(dirname "$0")/../.."
fernet() { python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())'; }
token() { python3 -c 'import secrets;print(secrets.token_urlsafe(32))'; }

# Per-host secrets in infra/.env (mode 600), created once and never overwritten.
umask 077
touch infra/.env
add() { grep -qs "^$1=" infra/.env || echo "$1=$2" >> infra/.env; }
add CONTENT_ENCRYPTION_KEY "$(fernet)"
add BROKER_ENCRYPTION_KEY "$(fernet)"
for t in CREDENTIAL_BROKER_TOKEN POLICY_PUBLISHER_TOKEN SIEM_TOKEN ORCHESTRATOR_TOKEN LLM_GATEWAY_TOKEN INTERCEPTOR_TOKEN USER_TOKEN_KEY; do
  add "$t" "$(token)"
done
# The LAN address people connect to (client certificate required) and the administrators' certificate names.
add TETHER_LAN_ADDRESS "$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
grep -qs '^TETHER_ADMIN_USERS=.' infra/.env || { echo "set TETHER_ADMIN_USERS=<your certificate name> in infra/.env" >&2; exit 1; }
umask 022

# Interceptor socket directory and gateway JWT public key (written by the gateway's generate-certs).
export TETHER_UID=$(id -u) TETHER_GID=$(id -g)
export TETHER_RUN_DIR=${XDG_RUNTIME_DIR:-/run/user/$TETHER_UID}/tether
export TETHER_JWT_PUBLIC_KEY=$HOME/.local/state/openshell/tls/jwt/public.pem
test -r "$TETHER_JWT_PUBLIC_KEY" || { echo "missing $TETHER_JWT_PUBLIC_KEY (run 20-openshell.sh first)" >&2; exit 1; }
mkdir -p -m 700 "$TETHER_RUN_DIR"

# TLS material from 60-tls.sh (run on the administrator's machine first).
export TETHER_TLS_DIR=$HOME/.local/state/tether/tls
for f in front.crt front.key inference.crt inference.key llm-gateway-client.crt llm-gateway-client.key service-ca.pem user-ca.pem user-ca.crl; do
  test -r "$TETHER_TLS_DIR/$f" || { echo "missing $TETHER_TLS_DIR/$f (run infra/staging/60-tls.sh from the admin machine)" >&2; exit 1; }
done
export ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.34.1@sha256:007da57c2c328a90bd4e6d99b70bd899132f1b4a9426ccafe25437cf84a60c14}

# Company provider profiles with the platform hosts as sandboxes see them on this host.
rm -rf infra/staging/out/profiles; mkdir -p infra/staging/out/profiles
for p in openshell/profiles/*.yaml; do
  sed -e 's/^\(  - host: \)llm-gateway\.company\.internal$/\1host.openshell.internal/' \
      -e 's/^\(  - host: \)policy-api\.company\.internal$/\1host.openshell.internal/' "$p" > "infra/staging/out/profiles/$(basename "$p")"
done
for p in tether-llm tether-policy; do
  grep -q '^  - host: host.openshell.internal$' "infra/staging/out/profiles/$p.yaml" || { echo "profile $p host not rewritten" >&2; exit 1; }
done

compose() { docker compose --env-file infra/.env -f infra/docker-compose.yml -f infra/staging/compose.staging.yml "$@"; }
compose up -d --build
for _ in $(seq 60); do curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8080/health && echo
for _ in $(seq 30); do test -S "$TETHER_RUN_DIR/gateway-interceptor.sock" && break; sleep 1; done
test -S "$TETHER_RUN_DIR/gateway-interceptor.sock" || { compose logs --tail 50 gateway-interceptor >&2; exit 1; }
compose ps
echo "interceptor socket: $TETHER_RUN_DIR/gateway-interceptor.sock"
