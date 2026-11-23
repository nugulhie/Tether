# Production checklist

Legend: [x] implemented in this repository · [ ] needs environment-specific work (owner action)

## Identity and transport
- [x] OIDC ID-token auth on the Policy API (`AUTH_MODE=oidc`, `OIDC_*`); groups from `OIDC_GROUPS_CLAIM`
- [x] Device identity from the mTLS proxy (`DEVICE_ID_HEADER`); launcher client cert (`client_cert`/`client_key`)
- [ ] Deploy the mTLS-terminating proxy in front of the Policy API and broker. It must verify client certs, overwrite `DEVICE_ID_HEADER`, and be the only route to the API.
- [ ] Issue device certificates via MDM (SCEP/ACME)

## Remote sandboxes and model access
- [x] Sandbox orchestrator: sole holder of gateway credentials; launch, terminal relay (WebSocket ↔ PTY), kill switch
- [x] LLM gateway: session-token-only, sandbox-egress-only, company keys, model allowlist, rate limit, usage audit
- [x] OpenShell provider profiles with credential endpoint binding (`openshell/profiles/`)
- [ ] Deploy the OpenShell gateway remotely (Kubernetes Helm chart) with OIDC/mTLS; give only the orchestrator a client identity
- [ ] Configure the gateway `upstreamProxy` with a fixed egress IP; set `SANDBOX_EGRESS_CIDRS` on the LLM gateway to it
- [ ] Replace hosts and `your-org` in `openshell/profiles/` (vended by the interceptor; no manual import). Add a `tether-aws.yaml` profile before granting `aws.role` in any policy (SigV4 re-signing endpoints); until then AWS grants fail closed at sandbox creation
- [ ] Sandbox image: Claude Code/Codex, `infra/mdm/out/sandbox/managed-settings.json` at `/etc/claude-code/managed-settings.json`, Codex provider config pointing at the gateway; git credential config compatible with the github-org profile (mirror the stock profile's auth style)
- [x] Gateway interceptor (`services/gateway-interceptor`): issued-name-only sandboxes, policy/provider replacement, widening and side doors denied, company profiles vended
- [ ] Deploy it with TLS, `GATEWAY_ID` and the gateway's extension public key; base the gateway configuration on `infra/openshell/gateway.toml` (run `openshell-gateway config preflight` on the gateway host); set `ALLOWED_SANDBOX_IMAGES`
- [ ] ~~GitHub IP allow list~~: not applied. Laptops keep GitHub access for remote work (decision 2026-10-02); `infra/github/` is kept for later use
- [ ] `BROKER_ENCRYPTION_KEY`, broker `iam:PutRolePolicy` on the agent role, persistent `BROKER_DB`

## Launcher
- [x] Thin client: login, launch, terminal; runs no OpenShell and holds no credentials
- [x] Managed config (`/Library/Application Support/Tether/config.json`, root-owned) overrides environment
- [x] Build script producing an ad-hoc signed binary and unsigned pkg (`agent-launcher/packaging/build-macos.sh`); no Apple Developer account needed
- [ ] Distribute the pkg via MDM (check your MDM accepts unsigned packages)

## OpenShell
- [x] Non-root sandbox (`process.run_as_user/group: sandbox`), Landlock `hard_requirement`
- [x] Network policy applied live on sandbox reuse (`openshell policy set --wait`)
- [ ] Managed OpenShell gateway: authenticate clients and refuse sandboxes whose policy hash is not one issued by the Policy API (closes the renamed-binary bypass)
- [ ] No broad host bind mounts: verify the gateway's sandbox driver configuration
- [ ] Network path from sandboxes to the Policy API for the Permission MCP

## Policy
- [x] GitOps repository (`policies/`), CI validation, Ed25519-signed bundles, replay/version checks, policy hash on sessions
- [ ] Branch protection on `main`, real CODEOWNERS team, `policy-publish` environment secrets, `POLICY_BUNDLE_PUBLIC_KEY` on the API

## Credentials
- [x] Credential broker: STS AssumeRole with SourceIdentity and session tags; GitHub App tokens scoped to one repo
- [ ] `AIAgentDevelopmentRole` with the trust policy in `services/credential-broker/README.md`; GitHub App installed on allowed repos

## Laptop control (MDM, no Apple entitlements)
- [x] Generator for the Claude Code managed settings profile/file and the sandbox managed settings (`infra/mdm/`, `make mdm`)
- [ ] Fill in `infra/mdm/config.yaml` (gateway URL, profile prefix)
- [ ] Pilot: `/status` in Claude Code shows the plist source; a laptop session fails against the gateway
- [ ] Deploy `claude-code.mobileconfig`; bake `sandbox/managed-settings.json` into the sandbox image

## Audit and response
- [x] OCSF events in the DB and as stdout JSON lines; SIEM pull API (`GET /v1/audit/events`, `SIEM_TOKEN`)
- [x] Kill switch (`POST /v1/admin/sessions/revoke`, `ADMIN_GROUPS`); runbook `docs/incident-response.md`
- [x] Policy rollback via reviewed revert (audited as `rollbacks`)
- [ ] Ship logs to the SIEM and configure the detection rules listed in the runbook
