# Sandbox orchestrator

The only component with OpenShell gateway credentials. OpenShell has no per-sandbox ACL (exec, connect and create all need the same `sandbox:write` scope), so developers must never hold gateway access.

## `POST /v1/launch`
Takes the user's OIDC token, plus the device certificate via the mTLS proxy and `DEVICE_ID_HEADER`.
1. Accepts only repositories in `GITHUB_ORG`.
2. Creates the session at the Policy API, presenting the user's token. The session token comes back only here.
3. Gets AWS/GitHub credentials from the broker with the user's token.
4. Creates or updates providers from the company profiles (secrets via environment, never argv):
   - `company-llm`: session token bound to the LLM gateway;
   - `company-policy`: session token bound to the Policy API `/v1/**`;
   - `github-org`: token bound to org paths;
   - `aws`.
5. On a new sandbox: creates it with the compiled policy, then clones the repository inside it. On reuse: refreshes providers and applies network policy live (`openshell policy set --wait`).
6. Returns a one-time, 60-second ticket.

## `WS /v1/attach?ticket=…&rows=&cols=`
Runs `openshell sandbox exec --tty` under a server-side PTY and relays it.
- Binary frames carry terminal bytes.
- Text frames carry `{"type":"resize"}` (client to server) and `{"type":"exit","code"}` (server to client).

## `POST /v1/admin/revoke`
The kill switch, authorized by the caller's admin token at the Policy API. It:
1. expires the sessions;
2. cuts their terminals;
3. deletes their sandboxes;
4. has the broker deny AWS sessions and revoke GitHub tokens.

Partial failures return 502 with details.

## Local-LLM agent jobs (ADR 0001, D1)
Local agents run only as jobs an administrator approved at the Policy API (`/v1/agent/jobs`, `/v1/admin/agent/jobs/{id}/approve`).
- `POST /v1/jobs/{id}/run`: a person runs a job (its owner or an administrator; the Policy API decides).
- Schedule: with `JOB_SCHEDULER=1` the orchestrator asks `GET /v1/agent/jobs/due` every `JOB_SCHEDULER_SECONDS` (60) and starts those. The Policy API enforces the interval and one run per job at a time, so these credentials cannot run a job more often than approved.
- A run creates the job's own sandbox (never a developer's), gets credentials from the broker with the orchestrator identity (a scheduled run has no person), and executes `LOCAL_AGENT_COMMAND` (JSON list, default `["company-local-agent"]`) non-interactively with `OPENAI_BASE_URL=<gateway>/local/v1`, `COMPANY_AGENT_MODEL`, `COMPANY_AGENT_TASK` and `COMPANY_AGENT_JOB`.
- Each run is bounded by the job's `max_runtime_seconds`. Afterwards the sandbox is deleted and the session ended. `agent.exit` records the return code, timeout, job and trigger.
- `POST /v1/admin/revoke` accepts `job_id`.
- The agent binary must be listed in the policy's `agent_binaries`, or OpenShell will not let it reach the LLM gateway.

## Configuration
`POLICY_API`, `CREDENTIAL_BROKER`, `ORCHESTRATOR_TOKEN`, `GITHUB_ORG`, `LLM_GATEWAY_URL`, `POLICY_API_PUBLIC_URL`, `DEVICE_ID_HEADER`, `OPENSHELL_BIN`, and the OpenShell gateway identity (`OPENSHELL_GATEWAY`, mTLS bundle or OIDC client credentials).

## Limits
Tickets and live relays are kept in memory, so run a single replica (or add a shared store) until that changes.
