#!/usr/bin/env bash
# Clean-VM install test (docs/install-design.md, section 7; docs/release.md): from a pristine Ubuntu 24.04 VM,
# do what a customer does and then run the end-to-end checks. Run on the VM host, from the repository root:
#   bash infra/testvm/install-test.sh <dir with tether-<v>.tar, .tar.sha256, .tar.sha256.sig> <version> <release key sha256>
# Steps: reset the VM -> prerequisites (Docker Engine from Docker's apt repository, as a customer would) ->
# a separate small filesystem as the "USB stick" -> check the bundle signature before unpacking -> tether-install ->
# confirm the firewall from a new SSH session -> tether-doctor -> infra/staging/50-e2e.py (no self-hosted model).
# TETHER_TEST_AUTH=oidc: sign-in with an IdP (AUTH_MODE=oidc) instead of personal certificates. A test IdP
# (infra/testvm/test-idp.py) runs in the VM as a container on 10.0.2.15:9000, like an IdP outside the server.
# Exit status: 0 only if the install, the self-check and every e2e check pass.
set -euo pipefail
src=${1:?directory with the signed bundle}; v=${2:?version}; fp=${3:?release key fingerprint (RELEASE_KEY_SHA256)}
cd "$(dirname "$0")/../.."
vm() { bash infra/testvm/testvm.sh "$@"; }
DIR=${TESTVM_DIR:-$HOME/tether-testvm}
copy() { scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$DIR/id_ed25519" \
           -P "${TESTVM_SSH_PORT:-2222}" "$@" ubuntu@127.0.0.1:; }
t0=$(date +%s)
step() { printf '\n### %s (%ds)\n' "$*" $(( $(date +%s) - t0 )); }

step "reset the VM"
vm reset

step "prerequisites: Docker Engine"
vm ssh 'sudo bash -s' < infra/testvm/prereq-docker.sh
vm ssh 'sudo docker version --format "Docker {{.Server.Version}}"'

step "removable media for the policy signing key"
vm ssh 'sudo truncate -s 64M /var/usb.img && sudo mkfs.ext4 -q -F /var/usb.img && sudo mkdir -p /mnt/usb && sudo mount -o loop /var/usb.img /mnt/usb'

AUTH=${TETHER_TEST_AUTH:-mtls}
IDP=http://10.0.2.15:9000
if [ "$AUTH" = oidc ]; then
  step "test IdP (AUTH_MODE=oidc)"
  copy infra/testvm/test-idp.py
  vm ssh "sudo docker run -d -q --name tether-test-idp --restart unless-stopped -p 10.0.2.15:9000:9000 -e ISSUER=$IDP \
    -e CLIENT_ID=tether-test -v \$HOME/test-idp.py:/idp.py:ro python:3.13-slim \
    sh -c 'pip install -q --root-user-action=ignore PyJWT[crypto]==2.10.1 && exec python /idp.py' >/dev/null
    for i in \$(seq 60); do curl -fsS $IDP/.well-known/openid-configuration >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1" \
    || { vm ssh 'sudo docker logs tether-test-idp' | tail -20; echo "the test IdP did not start"; exit 1; }
  echo "test IdP at $IDP"
  conf="AUTH_MODE=oidc OIDC_ISSUER=$IDP OIDC_ALLOW_HTTP=1 OIDC_CLIENT_ID=tether-test OIDC_HOSTED_DOMAINS=test.example
        TETHER_ADMIN_USERS=admin@test.example"
else
  conf="AUTH_MODE=mtls TETHER_ADMIN_USERS=admin"
fi

step "copy and check the bundle before unpacking"
copy "$src/tether-$v.tar" "$src/tether-$v.tar.sha256" "$src/tether-$v.tar.sha256.sig" "$src/tether-$v/release-key.pub"
vm ssh "set -e; [ \"\$(openssl pkey -pubin -in release-key.pub -outform DER | sha256sum | cut -d' ' -f1)\" = $fp ]
  openssl pkeyutl -verify -pubin -inkey release-key.pub -rawin -in tether-$v.tar.sha256 -sigfile tether-$v.tar.sha256.sig
  sha256sum -c tether-$v.tar.sha256 && tar -xf tether-$v.tar"

step "tether-install"
# shellcheck disable=SC2086  # $conf is a list of KEY=VALUE words
vm ssh "printf '%s\n' RELEASE_KEY_SHA256=$fp TETHER_ADDRESS=10.0.2.15 $(echo $conf) GITHUB_ORG=nugulhie \
  POLICY_SIGNING_KEY_EXPORT=/mnt/usb/policy-signing.key FIREWALL=on ADMIN_NETWORKS=10.0.2.0/24,10.250.0.0/24 \
  | sudo install -D -m 644 /dev/stdin /etc/tether/tether.conf"
rc=0; vm ssh "sudo ./tether-$v/install/tether-install /etc/tether/tether.conf" || rc=$?

step "confirm the firewall from a new SSH session"
vm ssh 'sudo /opt/tether/current/tether-install confirm-firewall'
[ "$rc" = 0 ] || { echo "tether-install failed ($rc)"; exit 1; }

step "tether-doctor (again, after the firewall is confirmed)"
vm ssh 'sudo tether-doctor'
vm ssh 'ls /opt/tether/current/clients/*.pkg' || { echo "the employee client is not installed with the bundle"; exit 1; }
if [ "$AUTH" = oidc ]; then
  vm ssh 'sudo tether-admin client && sudo cat /etc/tether/client/tether.json && ls /etc/tether/client'
  vm ssh "grep -q 'require_client_certificate: false' /opt/tether/current/envoy-front.yaml" \
    || { echo "tls-front still requires a client certificate"; exit 1; }
fi

step "end-to-end checks"
tar -czf - --exclude __pycache__ infra/staging/50-e2e.py services/sandbox-orchestrator/orchestrator > "$DIR/e2e.tgz"
copy "$DIR/e2e.tgz"
vm ssh 'rm -rf e2e && mkdir e2e && tar -xzf e2e.tgz -C e2e 2>/dev/null && cd e2e && sudo env HOME=/var/lib/tether \
  XDG_CONFIG_HOME=/var/lib/tether/.config XDG_STATE_HOME=/var/lib/tether/.local/state \
  TETHER_E2E_ENV=/etc/tether/compose.env E2E_NO_LOCAL_MODEL=1 E2E_OIDC_TEST_IDP='"$IDP"' python3 infra/staging/50-e2e.py'
step "passed"
