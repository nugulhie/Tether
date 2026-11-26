#!/usr/bin/env bash
# Tether's two certificate authorities, kept on the administrator's machine (never on the server).
#   service CA  name-constrained to the platform's own names; signs server certificates and service
#               client certificates. OpenShell trusts it for sandbox egress (additional_ca_bundle), so the
#               constraint keeps it from vouching for any other host a policy allows.
#   user CA     signs one client certificate per person (identity instead of SSO).
# Keys live in $TETHER_PKI (default ~/.tether-pki, mode 700). Requires OpenSSL 3.
#
#   tether-pki.sh init <server-ip>                 create both CAs (once)
#   tether-pki.sh sign-server <csr> <san> [days]   e.g. "DNS:host.openshell.internal,IP:127.0.0.1"
#   tether-pki.sh sign-client <csr> <san> [days]   service client certificate (e.g. the LLM gateway)
#   tether-pki.sh user <name> [days]               person certificate -> $TETHER_PKI/users/<name>/, a folder to hand
#                                                  over whole: cert.pem, key.pem, service-ca.crt and, when TETHER_SERVER
#                                                  is set (and optionally TETHER_MODEL), tether.json; then `tether setup <folder>`
#   tether-pki.sh revoke <name>                    revoke a person's certificate (then push the CRL: 60-tls.sh)
#   tether-pki.sh crl                              print the user CA's current CRL (valid 365 days; 60-tls.sh re-pushes it)
#   tether-pki.sh ca                               print the service CA certificate
# Certificates go to stdout (sign-*) so the caller decides where they land.
set -euo pipefail
PKI=${TETHER_PKI:-$HOME/.tether-pki}
OPENSSL=${OPENSSL:-openssl}
"$OPENSSL" version | grep -qE '^OpenSSL [3-9]' || { echo "OpenSSL 3 or later required (set OPENSSL=...)" >&2; exit 1; }
die() { echo "$*" >&2; exit 1; }

new_ca() {  # name, CN, extra -addext...
  local name=$1 cn=$2; shift 2
  [ -e "$PKI/$name.key" ] && die "$PKI/$name.key already exists"
  "$OPENSSL" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -sha256 -days 3650 \
    -keyout "$PKI/$name.key" -out "$PKI/$name.crt" -subj "/O=Tether/CN=$cn" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" "$@" 2>/dev/null
  chmod 600 "$PKI/$name.key"
}

sign() {  # ca, csr, eku, san, days
  local ca=$1 csr=$2 eku=$3 san=$4 days=$5 ext
  ext=$(mktemp); trap 'rm -f "$ext"' RETURN
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nauthorityKeyIdentifier=keyid\n%s' \
    "$eku" "${san:+subjectAltName=$san}" > "$ext"
  "$OPENSSL" x509 -req -in "$csr" -CA "$PKI/$ca.crt" -CAkey "$PKI/$ca.key" -CAserial "$PKI/$ca.srl" -CAcreateserial \
    -days "$days" -sha256 -extfile "$ext" 2>/dev/null
}

case ${1:-} in
  init)
    ip=${2:?server IP}; dns=${3:-}    # optional: the server's DNS name, when people reach it by name
    mkdir -p -m 700 "$PKI"; chmod 700 "$PKI"
    # host.openshell.internal: how sandboxes reach host services; tether.internal: names that exist only in
    # container host files (no DNS); the server address (and name) for clients on the LAN.
    new_ca service-ca "Tether service CA" \
      -addext "nameConstraints=critical,permitted;DNS:host.openshell.internal,permitted;DNS:tether.internal,permitted;IP:$ip/255.255.255.255,permitted;IP:127.0.0.1/255.255.255.255${dns:+,permitted;DNS:$dns}"
    new_ca user-ca "Tether user CA"
    echo "created $PKI/service-ca.{key,crt} and $PKI/user-ca.{key,crt}; back up $PKI offline" ;;
  sign-server) sign service-ca "${2:?csr}" serverAuth "${3:?san}" "${4:-397}" ;;
  sign-client) sign service-ca "${2:?csr}" clientAuth "${3:?san}" "${4:-397}" ;;
  user)
    name=${2:?name}; days=${3:-90}
    [[ $name =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "name must be lowercase letters, digits, . _ - (max 63)"
    d="$PKI/users/$name"; [ -e "$d/cert.pem" ] && die "$d/cert.pem exists (revoke or remove it first)"
    mkdir -p -m 700 "$d"
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$d/key.pem" 2>/dev/null; chmod 600 "$d/key.pem"
    "$OPENSSL" req -new -key "$d/key.pem" -subj "/O=Tether/CN=$name" -out "$d/req.csr"
    sign user-ca "$d/req.csr" clientAuth "" "$days" > "$d/cert.pem"; rm -f "$d/req.csr"
    cp "$PKI/service-ca.crt" "$d/service-ca.crt"
    if [ -n "${TETHER_SERVER:-}" ]; then
      python3 -c 'import json,sys; print(json.dumps({k:v for k,v in (("server",sys.argv[1]),("model",sys.argv[2])) if v}))' \
        "$TETHER_SERVER" "${TETHER_MODEL:-}" > "$d/tether.json"
    fi
    echo "$d (valid $days days): give the whole folder to $name over a private channel; they run: tether setup <folder>"
    [ -e "$d/tether.json" ] || echo "  no tether.json: set TETHER_SERVER (e.g. https://192.168.1.27) or they pass --server to tether setup" ;;
  revoke)
    name=${2:?name}; d="$PKI/users/$name"; [ -e "$d/cert.pem" ] || die "no certificate for $name"
    serial=$("$OPENSSL" x509 -in "$d/cert.pem" -noout -serial | cut -d= -f2)
    touch "$PKI/user-ca.revoked"; grep -qx "$serial" "$PKI/user-ca.revoked" || echo "$serial" >> "$PKI/user-ca.revoked"
    mv "$d" "$PKI/users/.revoked-$name-$serial"
    echo "revoked $name (serial $serial); push the CRL to the server now (60-tls.sh), and revoke the person's sessions" ;;
  crl)
    # openssl ca needs its database; rebuild a throwaway one from the revoked-serial list.
    work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
    touch "$work/index.txt"
    while read -r serial; do
      [ -n "$serial" ] && printf 'R\t991231235959Z\t%s\t%s\tunknown\t/CN=revoked\n' "$(date -u +%y%m%d%H%M%SZ)" "$serial" >> "$work/index.txt"
    done < <(cat "$PKI/user-ca.revoked" 2>/dev/null)
    printf '[ca]\ndefault_ca=c\n[c]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=sha256\ndefault_crl_days=365\n' "$work" "$work" > "$work/ca.cnf"
    echo 01 > "$work/crlnumber"
    "$OPENSSL" ca -gencrl -config "$work/ca.cnf" -keyfile "$PKI/user-ca.key" -cert "$PKI/user-ca.crt" -out /dev/stdout 2>/dev/null ;;
  ca) cat "$PKI/service-ca.crt" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
