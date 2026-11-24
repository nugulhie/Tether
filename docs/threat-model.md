# Threat model

**Security invariant:** an AI agent can reach a model, company code or company credentials only from a managed sandbox, under a policy-bound session that can be revoked.

**Assumptions:**
- Developers may be local administrators on their Macs.
- There is no host-level blocking on Macs, because Apple entitlements are unavailable.
- Laptops keep GitHub access, because remote work requires it.

## Bypass paths and how they are closed

| # | Bypass | Closed by | Holds against a local admin? |
|---|---|---|---|
| 1 | Run `openshell` directly (renamed or rebuilt) with a weak policy | Remote gateway; only the orchestrator holds gateway credentials; interceptor | Yes (no gateway credentials) |
| 2 | Run an agent in a local VM or container | No company model access: session tokens never reach the Mac | Company model: yes. Personal model: not blocked (residual 2) |
| 3 | Renamed or rebuilt agent, or a custom script calling a model API | Same as 2; the LLM gateway accepts only session tokens from sandbox egress | Yes, for company model access |
| 4 | Personal claude.ai login or a personal API key | The gateway never forwards client credentials. On laptops, Claude Code is pinned to the gateway (managed settings) | Gateway: yes. Laptop setting: no |
| 5 | Clone onto an unmanaged machine and run an agent there | Not blocked: laptops keep GitHub access (decision 2026-10-02). Company SSO and GitHub permissions still apply | No (residual 1) |
| 6a | Push company code to another repository or org | L7 rules allow github.com only on `/<org>/**`; the token placeholder is bound to org paths | Yes |
| 6b | Upload through a package registry (e.g. `npm publish` with a pasted token) | Registries are read-only (GET/HEAD/OPTIONS) unless a policy says otherwise | Yes |
| 6c | Send a credential placeholder to another allowed host to have it substituted | Static credential endpoint binding (`credential_endpoint_mismatch`) | Yes |
| 7 | Point the launcher at a fake control plane | Managed root-owned config; the control plane is server-side anyway | Yes |
| 8 | Keep using credentials or a sandbox after revocation | Orchestrator kill switch: tokens expire, terminals are cut, sandboxes deleted, the STS session is denied by tag, the GitHub token revoked; the LLM gateway refuses within 15 s | Yes |
| 9 | Policy tampering or replay | Signed bundles, monotonic serials, version checks, CODEOWNERS | Yes |
| 10 | Stolen orchestrator (gateway) credentials used to create or widen a sandbox | Gateway interceptor (fail-closed, exact bindings): sandboxes only under Policy-API-issued names; policy and providers replaced with the issued ones; widening, side-door access and profile changes denied | Yes |
| 11 | Stock or attacker-defined provider profiles (e.g. the broad `github` profile) | The interceptor is the gateway's only profile source and denies profile imports | Yes |

### Self-hosted models and guardrails ([ADR 0001](adr/0001-local-llm-agent-control.md))

| # | Bypass | Closed by | Holds against a local admin? |
|---|---|---|---|
| G-1 | Call a GPU inference server directly from a laptop or the office network | Inference servers accept only the LLM gateway (network allow-list + mTLS client certificate; infrastructure) | Yes, once the network rule is in place |
| G-2 | Allow a GPU inference host in a sandbox policy | `PLATFORM_LOCAL_INFERENCE_HOSTS`: the Policy API refuses such bundles and sessions; the interceptor enforces issued policies | Yes |
| G-3 | A local agent exfiltrates data through tool calls or its output | OpenShell L7 policy, output guardrails, prompt/response content audit | Yes |
| G-4 | Make the guardrail fail so requests go through unchecked | Fail-closed: a guardrail error refuses the request or ends the stream | Yes |
| G-5 | Leave a break-glass bypass open, or abuse it | Mandatory scope and TTL (max `GUARDRAIL_BYPASS_MAX_SECONDS`), expiry enforced by the gateway clock, start/end events, SIEM alert | Yes |
| G-6 | Load tampered weights or an inference image (pickle RCE) | Ed25519-signed weight manifests (safetensors only, re-hashed at start) and cosign-verified image digests, before the engine starts (`infra/gpu/signing/`); not bypassable by break-glass | Yes, once deployed |
| G-7 | Change the serving configuration over SSH on a GPU server | SSH only from the bastion, admin group only, tlog session recording and auditd (`infra/gpu/network/`) | Yes, once deployed |
| G-9 | Run an unapproved local agent, or change an approved job's task | Local agents run only as jobs; the Policy API issues a session only for an approved job, approved by an administrator other than its owner; jobs are immutable (a change is a new job) | Yes |
| G-10 | Stolen orchestrator credentials run a job continuously or as someone else | The Policy API enforces the job's interval, one run at a time, and owner-or-admin for manual runs; the orchestrator can read only job sessions | Yes |
| G-11 | Allow a host alias in a policy (`host.openshell.internal` is host loopback) to reach the inference engine or other host services from a sandbox | The compiler refuses host aliases, address literals and the platform hosts in `network.allow`; the platform endpoints are compiled in for agent binaries only, on :443 | Yes |
| G-12 | Claim to be another person (no SSO, `AUTH_MODE=mtls`) | The front verifies the client certificate (user CA, CRL) and overwrites the identity headers; the Policy API accepts them only from the front's address, and the sandbox listener refuses `/v1/auth/`. Tokens last one hour | Yes |
| G-13 | Rewrite or delete audit history on the server | Hash chain over audit events (`app/audit_chain.py`); the administrator's daily pull backup keeps the last head off the server, so even a re-hashed chain no longer matches | Detects, does not prevent |
| G-8 | Run a model request without it being on record | The prompt is stored (encrypted) before it is sent upstream; if storage fails the request is refused | Yes |

## Residual risks (outside what software on the Mac can enforce)
1. **Company code on laptops and other machines.** Laptops keep GitHub access for remote work (`infra/github/sync_ip_allow_list.py` is kept but not applied). Whatever a developer can clone or view can be handed to tools outside the platform. Handling this is DLP and acceptable-use policy, plus GitHub's own SSO and permissions.
2. **Personal AI on laptops.** There is no host-level blocking. The only laptop control, the Claude Code managed settings, covers Claude Code and nothing else (not Codex, IDE assistants or browsers), and an administrator can remove it. Company model access, sandboxes and credentials are unaffected. A company EDR or SWG, if one becomes available, can add host or network blocking later.
3. **Exec with stolen gateway credentials.** OpenShell's exec, interactive exec and port-forward RPCs are streaming RPCs and cannot be intercepted. Stolen orchestrator credentials could open a shell in an existing sandbox (one that is already confined to its issued policy). Keep the orchestrator identity short-lived and dedicated.
4. **Unrecognized model hosts.** The compiler keeps a list of known SaaS model providers out of sandbox policies; new providers need list updates. Company GPU inference hosts are no longer a residual risk: they are named in `PLATFORM_LOCAL_INFERENCE_HOSTS` and accept only the LLM gateway (G-1, G-2).
5. **Rule-based guardrails.** The first guardrails are regular expressions: they catch common credentials and Korean personal data, not paraphrased or encoded leaks. A secret split across stream events is caught, but the part already sent before the match is not recalled. `deny_patterns` come from reviewed policy; a pathological regex there can slow the gateway.
6. **Stored prompts are sensitive.** Every prompt and response is kept (encrypted). Whoever holds `CONTENT_ENCRYPTION_KEY` and database access can read them; reads through the API are admin-only and audited.
7. **Credential placeholders are endpoint-scoped, not binary-scoped (OpenShell v0.1.9).** A provider's static placeholder resolves for any request to that provider's profile endpoints once some rule admits the calling binary and the destination; `binaries` (in profiles and in `agent_binaries`/`network_binaries`) gate network admission only. Binaries match by real path or any ancestor process, so every process an admitted agent starts (node runs claude/codex) is admitted too. Within a sandbox, anything that reaches the LLM gateway or Policy API can therefore use the session token there; it still cannot carry the token to another host (6c), and the session token is valid only for that session.
8. **Single host (on-premises deployment, `infra/staging/`).** The control plane, OpenShell gateway, inference engine and their keys share the GPU server, and the `docker` group is root-equivalent there. Whoever takes the host can change policy and records; the CA and policy-signing keys stay on the administrator's machine, and the off-server audit head (G-13) shows rewritten history, but neither restores control of the host.
9. **One administrator.** With `SINGLE_ADMIN_APPROVAL=1` the only administrator approves their own jobs and nobody reviews break-glass in real time; the records (`self_approved`, bypass events) are the only check.
