# Incident response runbook

## Contain
One call, as a member of `ADMIN_GROUPS`:

```bash
curl -X POST https://agents.company.internal/v1/admin/revoke -H "Authorization: Bearer $ADMIN_ID_TOKEN" \
  -d '{"user_id": "kim@company.com", "reason": "INC-42"}'   # or session_id / device_id / {"all": true}
```

The orchestrator then does all of the following:
1. Expires the session tokens at the Policy API. Permission checks, the LLM gateway (within 15 s) and the broker refuse them.
2. Cuts live terminals for those sessions.
3. Deletes their sandboxes on the gateway.
4. Asks the broker to revoke issued credentials:
   - AWS: an inline deny policy `CompanyAgentRevokedSessions` on the agent role, keyed on the `session_id` principal tag;
   - GitHub: the installation token is revoked.

A non-200 response lists what did not complete; finish those steps by hand:
- `openshell sandbox delete`;
- an AWS deny policy on `aws:TokenIssueTime`;
- suspending the GitHub App installation.

**Tighten policy if needed.** Merge a policy change (bump `version`). Sessions on the superseded version immediately get `POLICY_SUPERSEDED` and lose model access.

## Investigate
Pull OCSF events with `GET /v1/audit/events?after_id=...` (SIEM token or admin), or search the SIEM:
- `session.create`: who, which device (`device.is_trusted` = mTLS-verified), repo, policy version and hash.
- `permission.check`: what the agent asked for and the decision.
- `credential.issue`: AWS role/duration, GitHub repo/permissions. Correlate AWS activity in CloudTrail by `SourceIdentity` = user and the `session_id` tag.
- `llm.request`: every model call — session, model, token usage, `request_id`, whether content was stored, and the guardrail outcome (`guardrail.bypassed`, `blocked`, `error`).
- `llm.content`: the stored prompt/response for a `request_id` (id and hash only in the event). To read a body, as an administrator, with a reason that is itself audited:
  ```bash
  curl -H "Authorization: Bearer $ADMIN_ID_TOKEN" "https://policy-api.company.internal/v1/audit/content?request_id=<id>"
  curl -H "Authorization: Bearer $ADMIN_ID_TOKEN" "https://policy-api.company.internal/v1/audit/content/<content_id>?reason=INC-42"
  ```
- **Retention:** bodies are deleted after `CONTENT_RETENTION_DAYS` (90). At the start of an incident, place a legal hold first so the evidence survives the next purge, and release it when the case closes:
  ```bash
  curl -X POST -H "Authorization: Bearer $ADMIN_ID_TOKEN" -H 'Content-Type: application/json' \
    -d '{"scope":"user","value":"kim","reason":"INC-42"}' https://policy-api.company.internal/v1/admin/audit/content/holds
  curl -X DELETE -H "Authorization: Bearer $ADMIN_ID_TOKEN" "https://policy-api.company.internal/v1/admin/audit/content/holds/<hold_id>?reason=INC-42%20closed"
  ```
  Scopes are `user`, `session` and `job` (scheduled runs belong to `job:<id>`, so hold them by job). Purged content returns 404; its `llm.content` event (id, hash, size) remains.
- `guardrail.block` / `guardrail.error`: what was blocked (rule names, direction), or that a guardrail failed and the request was refused.
- `policy.publish` and `session.revoke`: control-plane changes, including `rollbacks`.

## Local-LLM agent jobs
- Stop a job's runs now: `POST /v1/admin/revoke` on the orchestrator with `{"job_id": "<id>", "reason": "..."}` (sessions expire, the sandbox is deleted, credentials revoked).
- Stop future runs: `POST /v1/admin/agent/jobs/<id>/disable` on the Policy API with `{"reason": "..."}`. A disabled job never starts again; a changed task is a new job and needs a new approval.
- Investigate with `session.create` (`job_id`, `trigger`, `triggered_by`), `agent.exit` (`returncode`, `timed_out`), and `agent.job.request/approve/reject/disable` (`task_sha256` ties a run to the approved task). Scheduled runs act as `job:<id>`; AWS CloudTrail shows `SourceIdentity` `job_<id>`.

## Guardrail outage (break-glass)
Guardrails fail closed: while they are broken, model requests are refused. If that outage is worse than running without them, an administrator can lift them for a scope and a limited time:

```bash
curl -X POST https://policy-api.company.internal/v1/admin/guardrails/bypass -H "Authorization: Bearer $ADMIN_ID_TOKEN" \
  -d '{"scope": "model", "target": "company-coder-*", "ttl_seconds": 3600, "reason": "INC-51 guardrail classifier down"}'
# scope: all | policy | user | session | model (target required except for all)
curl -X DELETE "https://policy-api.company.internal/v1/admin/guardrails/bypass/<id>?reason=classifier%20restored" -H "Authorization: Bearer $ADMIN_ID_TOKEN"
```

- Only guardrails are lifted. Session and source checks, model allow-lists, network policy and content audit keep running, and every request in the window is marked `guardrail.bypassed: true`.
- It takes effect within 15 s (gateway session cache). It ends at `expires_at` exactly; the TTL cannot exceed `GUARDRAIL_BYPASS_MAX_SECONDS` (default 4 h).
- Afterwards, review the window's `llm.content` for what passed unchecked.

## Recover
- **Roll back policy:** revert the policy commit. CI publishes it as a new signed bundle, and the API records it under `rollbacks`.

## Detection rules to configure in the SIEM
- A device that created sessions but has no heartbeat for more than `ENDPOINT_HEARTBEAT_MAX_AGE`.
- `policy.publish` with `signed: false` outside development, or with non-empty `rollbacks`.
- Bursts of `permission.check` DENY for one session.
- Any `guardrail.bypass.start` (page the security on-call), and `llm.request` with `guardrail.bypassed: true` outside an open bypass window.
- `guardrail.error` bursts (guardrail outage) and `guardrail.block` bursts for one session or user.
- `llm.request` with `content_stored: false` (a response could not be stored).
- `audit.content.read` outside an open incident.
- `audit.content.purge` missing for more than a day (the purge job stopped), or with `status_id=2`; `audit.content.hold.end` without a closed incident.
- `model.verify` / `image.verify` with `result` other than success (logged by the GPU hosts, `infra/gpu/signing/`), and nftables drop logs from GPU hosts (`infra/gpu/network/`).
- `agent.job.approve` where `decided_by` and the requester share a team you consider one person, and `agent.exit` with `timed_out: true` repeatedly for one job.
