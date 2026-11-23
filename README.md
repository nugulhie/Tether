# Company AI Agent Security Platform

OpenShell-based enterprise control plane for Claude Code / Codex. Agents run only in remote, managed sandboxes and reach models only through the company LLM gateway. Start with `docs/overview.md` (development status, phases and end-to-end flows), then `docs/architecture.md` and `docs/threat-model.md`.

```text
company-agent (terminal) ─► Sandbox orchestrator ─► Policy API · Credential broker · OpenShell gateway ─► Sandbox ─► LLM gateway ─► models
Laptops (MDM): Claude Code pinned to the LLM gateway
```

## Important boundaries
- Developer machines are terminals. They never hold a session token, gateway credential, or cloud/GitHub credential.
- The orchestrator is the only holder of OpenShell gateway credentials. The gateway interceptor makes the Policy API, not the caller, the authority for what a sandbox may be.
- OpenShell (Supervisor, L7 network rules, credential endpoint binding) is the runtime enforcement boundary.
- The LLM gateway is the only route to a model.
- The laptop control (MDM-delivered Claude Code managed settings, `infra/mdm/`) deters personal use of Claude Code. They need no Apple entitlements and can be tampered with by a local administrator, so nothing relies on them.

## Quick start

```bash
cd infra && docker compose up --build
```

Then install OpenShell using NVIDIA's official installer and verify `openshell --help`.

```bash
make launcher
company-agent login          # OIDC device flow; needs COMPANY_OIDC_ISSUER, COMPANY_OIDC_CLIENT_ID
company-agent claude         # inside a clone of a repository in the company GitHub org
```

With the local compose stack (`AUTH_MODE=dev`), skip login and use `export COMPANY_AGENT_TOKEN=dev:$USER COMPANY_ORCHESTRATOR=http://localhost:8083`. Launching needs the OpenShell CLI and a gateway identity in the orchestrator container.

## Identity and credentials
- Users authenticate to the Policy API with an OIDC ID token. Behind an mTLS proxy, `DEVICE_ID_HEADER` makes the client certificate the device identity (launcher: `COMPANY_CLIENT_CERT`, `COMPANY_CLIENT_KEY`).
- Only the orchestrator can create sessions, and it must present the user's own token. The session token goes into the sandbox as OpenShell provider credentials bound to the LLM gateway and Policy API hosts. Permission checks and model calls take identity from the session, never from the request.
- The credential broker issues STS and GitHub App credentials scoped to the session. The orchestrator attaches them as OpenShell providers bound to their destinations, so the agent only sees placeholders. Issued credentials are recorded so the kill switch can revoke them.
- Audit events are OCSF-normalized, stored in `audit_events` and written to stdout as JSON lines for SIEM shipping.

The launcher expects the current directory to be a Git repository and calls `POST /v1/agent/sessions` before creating an OpenShell sandbox.

The Policy API compiles company policy into OpenShell policy with `services/policy-compiler` and returns it as `openshell_policy`; the launcher only writes it out. Sandboxes are named from user + repo + policy hash, so a policy change creates a new sandbox.

## Tests

```bash
make test
```

## Policy management (GitOps)
Policies live in `policies/*.yaml` and change only through reviewed pull requests (`.github/CODEOWNERS`, branch protection on `main`).
- Pull request: CI runs `company-policy validate policies` and the compiler tests.
- Merge to `main`: CI builds a bundle (serial = commit count on `main`), signs it with Ed25519 and posts it to `POST /v1/policies/bundle`.
- The Policy API checks the signature (`POLICY_BUNDLE_PUBLIC_KEY`) and refuses a bundle if:
  - its serial is not newer than the last bundle (replay),
  - a policy changed without a version bump,
  - a new version is lower than the published one.
- Re-publishing an identical older version is allowed as an audited rollback.
- Each session pins the exact `policy_id`/`version` and `policy_hash` it started with. When that version is superseded, permission checks return `POLICY_SUPERSEDED` and the credential broker refuses new credentials.
- Selection: the highest-`priority` active policy whose `match` (repo glob on `host/owner/repo`, environments, OIDC groups) fits. No match means no session.
- Network changes reach running sandboxes on the next launch (`openshell policy set`). Filesystem, process and credential changes create a new sandbox.

```bash
company-policy keygen signing.pem signing.pub   # once; store signing.pem as a CI secret
make policy-validate
```

Schema changes are Alembic migrations in `services/policy-api/app/migrations`. They run on startup unless `MIGRATE_ON_STARTUP=0`.
