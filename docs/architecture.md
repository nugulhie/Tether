# Architecture

Agents run only in remote, managed OpenShell sandboxes. Developer machines are terminals: they hold no session token, no gateway credential and no cloud/GitHub credential.

```text
Mac (company-agent)                      Control plane                               Data plane (managed gateway)
  login (OIDC) ──────────────┐
  POST /v1/launch ───────► Sandbox orchestrator ──► Policy API: session (user token + device)
  WS /v1/attach  ◄═══PTY═══►      │                 Credential broker: STS / GitHub App token
                                  │ (only holder of gateway creds)
                                  └──► openshell: providers, sandbox create, policy set, exec, delete ──► Sandbox
                                                                                                       │ egress proxy (fixed IP)
                                       LLM gateway ◄── session token (placeholder → real at egress) ◄──┤
                                       (company keys) ──► Anthropic / OpenAI                           ├──► GitHub (org paths only)
                                                                                                       └──► registries (read-only)
Mac (MDM): Claude Code pinned to the LLM gateway
```

## Choke points
Each of these holds even if the developer is a local administrator.

1. **Model access.** The only route to a model is the LLM gateway. It requires:
   - an agent session token, which exists only inside sandboxes as an OpenShell placeholder bound to the gateway host;
   - a source address in the sandbox egress range.

   It holds the company keys and never forwards client credentials, including personal claude.ai logins. Policies cannot allow model provider hosts directly (the compiler rejects them).
2. **Sandbox control.** OpenShell has no per-sandbox ACL: anyone who can exec can also create. So only the orchestrator holds gateway credentials. Developers get a one-time, 60-second ticket for one terminal on one sandbox.

   Behind that, the **gateway interceptor** (fail-closed) lets a sandbox exist only under a name the Policy API issued to an active session. Its policy and providers are replaced with the issued ones, and later widening (policy updates, provider attachment, draft approvals, SSH, service exposure, profile changes) is denied. Stolen orchestrator credentials therefore cannot produce a weaker sandbox.
3. **Code access from agents.** Inside sandboxes:
   - GitHub is reachable only on `/<org>/**` paths (L7 rules);
   - the GitHub token placeholder is substituted only for those paths (`openshell/profiles/github-org.yaml`).
4. **Credentials.** Session-scoped and short-lived. Every credential and every sandbox can be revoked in one call (`POST /v1/admin/revoke` on the orchestrator).

## Self-hosted models, guardrails and content audit ([ADR 0001](adr/0001-local-llm-agent-control.md))
- **Local inference.** The gateway's `local` provider reaches company GPU inference servers (OpenAI-compatible) with a client certificate; the servers accept nothing else. Policies grant `llm.local.models`; policies that allow a host in `PLATFORM_LOCAL_INFERENCE_HOSTS` are refused at publish and at session creation.
- **Guardrails.** A policy's `guardrails` section (secrets, Korean PII, deny patterns; input and output) is enforced by the gateway for every provider. Errors deny (fail-closed). An administrator can lift guardrails for a scope and a TTL (`/v1/admin/guardrails/bypass`); nothing else is lifted.
- **Local-agent jobs.** Local-LLM agents run only as administrator-approved jobs (approver ≠ owner), started by the owner or an administrator (`POST /v1/jobs/{id}/run`) or by the schedule (the Policy API decides what is due). Each run gets the job's own sandbox and a session no longer than the job's runtime limit, runs non-interactively, and is torn down afterwards.
- **Content audit.** Every prompt and response is stored encrypted by the Policy API (`CONTENT_ENCRYPTION_KEY`). The prompt is stored before it is sent upstream, or the request is refused. Audit events carry only ids and hashes; reading a body is admin-only and audited.

## Policy
- **GitOps.** Policies live in `policies/`; CI publishes them as signed bundles. Sessions pin a version.
- **What the compiler emits:**
  - filesystem, Landlock and the non-root process identity (static, part of the sandbox name);
  - network policies (live, `openshell policy set`), with registries read-only by default;
  - GitHub org-scoped rules;
  - platform endpoints (LLM gateway, Policy API) reachable only by agent binaries.

## Laptop control (defense in depth, no Apple entitlements)
Delivered by MDM from `infra/mdm/`: **Claude Code managed settings**. `allowedProviders: ["customEndpoint"]` plus a managed `ANTHROPIC_BASE_URL` pin Claude Code to the LLM gateway. The gateway serves sandbox egress only, so Claude Code on a laptop has no model access, personal logins included.

Laptops otherwise keep normal network and GitHub access, which remote work requires. There is no host-level blocking of other AI tools, and a local administrator can remove the profile. The guarantees above do not depend on it. See `threat-model.md`.
