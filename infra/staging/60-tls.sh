#!/usr/bin/env bash
# Issue the server's TLS certificates. Run on the administrator's machine (where the CA keys are):
#   bash infra/staging/60-tls.sh soldoc@192.168.1.27 192.168.1.27
# Private keys are generated on the server and never leave it; only CSRs come here to be signed by
# infra/pki/tether-pki.sh. Re-running renews every certificate (keys are kept). No sudo.
#   front               TLS front for sandboxes (host.openshell.internal) and LAN clients (server IP)
#   inference           envoy mTLS proxy in front of the inference engine (gpu-01.gpu.tether.internal)
#   llm-gateway-client  the LLM gateway's client certificate for that proxy (llm-gateway.tether.internal)
# Rollback: rm -rf ~/.local/state/tether/tls on the server.
set -euo pipefail
dest=${1:?ssh destination, e.g. soldoc@192.168.1.27}; ip=${2:?server IP}
pki="$(cd "$(dirname "$0")/../pki" && pwd)/tether-pki.sh"
[ -e "${TETHER_PKI:-$HOME/.tether-pki}/service-ca.key" ] || bash "$pki" init "$ip"

# name|server-or-client|subjectAltName  (bash 3 compatible: no associative arrays)
certs="front|server|DNS:host.openshell.internal,IP:127.0.0.1,IP:$ip
inference|server|DNS:gpu-01.gpu.tether.internal
llm-gateway-client|client|DNS:llm-gateway.tether.internal"
names=$(cut -d'|' -f1 <<<"$certs" | tr '\n' ' ')

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
# Keys and CSRs on the server (EC P-256, mode 600 in a 700 directory).
ssh "$dest" "set -e; d=~/.local/state/tether/tls; mkdir -p -m 700 \"\$d\"; cd \"\$d\"
  for n in $names; do
    [ -e \"\$n.key\" ] || (umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out \"\$n.key\")
    openssl req -new -key \"\$n.key\" -subj \"/O=Tether/CN=\$n\" -out \"\$n.csr\"
  done"
while IFS='|' read -r n kind san; do
  scp -q "$dest:.local/state/tether/tls/$n.csr" "$work/$n.csr"
  bash "$pki" "sign-$kind" "$work/$n.csr" "$san" > "$work/$n.crt"
done <<<"$certs"
bash "$pki" ca > "$work/service-ca.pem"
scp -q "$work"/*.crt "$work/service-ca.pem" "$dest:.local/state/tether/tls/"
ssh "$dest" 'cd ~/.local/state/tether/tls && rm -f ./*.csr && chmod 644 ./*.crt service-ca.pem &&
  for n in *.crt; do openssl verify -CAfile service-ca.pem "$n" >/dev/null && echo "$n: $(openssl x509 -in "$n" -noout -enddate)"; done'
