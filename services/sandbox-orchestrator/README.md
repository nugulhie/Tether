# Sandbox orchestrator

The only component with OpenShell gateway credentials. OpenShell has no per-sandbox ACL (exec, connect and create all need the same `sandbox:write` scope), so developers must never hold gateway access.

## `POST /v1/launch`
Takes the user's OIDC token, plus the device certificate via the mTLS proxy and `DEVICE_ID_HEADER`.
1. Accepts only repositories in `GITHUB_ORG`.
2. Creates the session at the Policy API, presenting the user's token. The session token comes back only here.
3. Gets AWS/GitHub credentials from the broker with the user's token.
4. Creates or updates providers from the company profiles (secrets via environment, never argv):
   - `tether-llm`: session token bound to the LLM gateway;
   - `tether-policy`: session token bound to the Policy API `/v1/**`;
   - `github-org`: token bound to org paths;
   - `aws`.
5. On a new sandbox: creates it (`openshell sandbox create --from $SANDBOX_IMAGE --detach --no-auto-providers`) with the compiled policy, then clones the repository inside it into `/workspace/<repo>`. On reuse: refreshes providers and applies network policy live (`openshell policy set --wait`).
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
- A run creates the job's own sandbox (never a developer's), gets credentials from the broker with the orchestrator identity (a scheduled run has no person), and executes `LOCAL_AGENT_COMMAND` (JSON list, default `["tether-agent"]`) non-interactively with `OPENAI_BASE_URL=<gateway>/local/v1`, `TETHER_MODEL`, `TETHER_TASK_FILE` and `TETHER_JOB`. The task text is written to `/workspace/.tether-task` through stdin of a separate exec first, so it never appears in argv or process listings. The agent is `local-agent/` (image: `infra/sandbox-images/local-agent`); it authenticates with the `tether-llm` provider placeholder in `TETHER_LLM_TOKEN`.
- The job sandbox is created from `LOCAL_AGENT_IMAGE`. The task is limited to 4 MiB, because `openshell sandbox exec` accepts at most 4 MiB of piped stdin; a larger task is refused (422) before a sandbox is created.
- Each run is bounded by the job's `max_runtime_seconds`. Afterwards the sandbox is deleted and the session ended. `agent.exit` records the return code, timeout, job and trigger.
- `POST /v1/admin/revoke` accepts `job_id`.
- The agent binary must be listed in the policy's `agent_binaries`, or OpenShell will not let it reach the LLM gateway.

## Sandbox images and the workspace
OpenShell v0.1.9 `sandbox create` has no `--workdir`. On Docker the image's `WORKDIR` becomes the workspace, and an image with no `WORKDIR`, `/` or `/sandbox` gets `/sandbox`. Every approved image must therefore declare `WORKDIR /workspace`, owned by the sandbox user (see `infra/sandbox-images/local-agent/Dockerfile`): clones, the job task file and the compiled policy's `read_write` all use `/workspace`.

`SANDBOX_IMAGE` (interactive agents) and `LOCAL_AGENT_IMAGE` (jobs) must be digest-pinned references (`name@sha256:…`); the orchestrator refuses to create a sandbox otherwise. They must also be listed in the gateway interceptor's `ALLOWED_SANDBOX_IMAGES`, which denies any create without an image.

Non-interactive execs (clone, task delivery, job runs) use `--no-tty --no-login-shell`, so sandbox-user profile files never run before automation.

## Configuration
`SANDBOX_IMAGE`, `LOCAL_AGENT_IMAGE`, `POLICY_API`, `CREDENTIAL_BROKER`, `ORCHESTRATOR_TOKEN`, `GITHUB_ORG`, `LLM_GATEWAY_URL`, `POLICY_API_PUBLIC_URL`, `DEVICE_ID_HEADER`, `OPENSHELL_BIN`, and the OpenShell gateway identity (`OPENSHELL_GATEWAY`, mTLS bundle or OIDC client credentials).

## Limits
Tickets and live relays are kept in memory, so run a single replica (or add a shared store) until that changes.
