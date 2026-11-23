# LLM gateway

The only route from agents to a model. Claude Code uses it via `ANTHROPIC_BASE_URL=https://<gateway>/anthropic` and `ANTHROPIC_AUTH_TOKEN`. Codex uses a custom provider with base URL `https://<gateway>/openai/v1`.

## What it accepts
- **Credential:** an agent session token (`ast_…`), in `Authorization: Bearer` or `x-api-key`. In sandboxes it exists only as an OpenShell placeholder bound to this host (`openshell/profiles/tether-llm.yaml`).
- **Source:** addresses in `SANDBOX_EGRESS_CIDRS`. `X-Forwarded-For` is honored only from `TRUSTED_PROXY_CIDRS`.
- **Session check:** `POST /v1/sessions/introspect` on the Policy API, cached 15 s. Revoked, expired, superseded and production sessions are refused.
- **Routes:**
  - Anthropic: `POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models` (filtered to the policy's models)
  - OpenAI: `POST /v1/responses`, `GET /v1/models`
- **Limits:** model allowlist (`llm.<provider>.models`, globs) and `llm.max_requests_per_minute` per session.

## Forwarding rules
These follow the Claude Code gateway compatibility guide.
- Request bodies are forwarded byte-for-byte; responses are streamed unbuffered (SSE pings included).
- `anthropic-*` headers are forwarded. `anthropic-beta` is forwarded verbatim except `oauth-*` values.
- Client credentials, cookies and other headers are never forwarded. The upstream receives the company key.
- Error bodies and `retry-after`, `x-should-retry`, `anthropic-ratelimit-*` are passed through.

## Audit
Each request is recorded as an OCSF `llm.request` event: session, user, model, status, token usage, duration, `request_id` and the guardrail outcome. Prompt and response bodies are stored separately, encrypted, by the Policy API (`/v1/audit/content`); the prompt is stored before it is sent upstream, and the request is refused if it cannot be. See [ADR 0001](../../docs/adr/0001-local-llm-agent-control.md).

## Self-hosted models and guardrails
- `local` provider: `/local/v1/chat/completions`, `/local/v1/completions`, `/local/v1/models` on `LOCAL_UPSTREAM` (https with `LOCAL_CLIENT_CERT`, `LOCAL_CLIENT_KEY`, optional `LOCAL_CA_BUNDLE`; `LOCAL_ALLOW_PLAINTEXT=1` for development only).
- Guardrails (`gateway/guardrails.py`) come from the session policy's `guardrails` section and apply to every provider. Prompts are checked before they are sent; streamed responses are checked event by event and ended with an error event on a violation; JSON responses are checked before any byte is sent. A guardrail error refuses the request (fail-closed). An administrator's bypass, returned by the Policy API with the session, lifts guardrails only.
- `CONTENT_MAX_BYTES` (default 16 MiB): larger prompts are refused (413); larger responses are stored truncated and flagged.

## Configuration
`POLICY_API`, `LLM_GATEWAY_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `SANDBOX_EGRESS_CIDRS`, `TRUSTED_PROXY_CIDRS`. Set `LLM_GATEWAY_ALLOW_ANY_SOURCE=1` for local development only.
