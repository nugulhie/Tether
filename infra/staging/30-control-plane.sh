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
for t in CREDENTIAL_BROKER_TOKEN POLICY_PUBLISHER_TOKEN SIEM_TOKEN ORCHESTRATOR_TOKEN LLM_GATEWAY_TOKEN INTERCEPTOR_TOKEN; do
  add "$t" "$(token)"
done
umask 022

# Interceptor socket directory and gateway JWT public key (written by the gateway's generate-certs).
export TETHER_UID=$(id -u) TETHER_GID=$(id -g)
export TETHER_RUN_DIR=${XDG_RUNTIME_DIR:-/run/user/$TETHER_UID}/tether
export TETHER_JWT_PUBLIC_KEY=$HOME/.local/state/openshell/tls/jwt/public.pem
test -r "$TETHER_JWT_PUBLIC_KEY" || { echo "missing $TETHER_JWT_PUBLIC_KEY (run 20-openshell.sh first)" >&2; exit 1; }
mkdir -p -m 700 "$TETHER_RUN_DIR"

compose() { docker compose --env-file infra/.env -f infra/docker-compose.yml -f infra/staging/compose.staging.yml "$@"; }
compose up -d --build
for _ in $(seq 60); do curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8080/health && echo
for _ in $(seq 30); do test -S "$TETHER_RUN_DIR/gateway-interceptor.sock" && break; sleep 1; done
test -S "$TETHER_RUN_DIR/gateway-interceptor.sock" || { compose logs --tail 50 gateway-interceptor >&2; exit 1; }
compose ps
echo "interceptor socket: $TETHER_RUN_DIR/gateway-interceptor.sock"
