"""LLM gateway: the only route from agents to a model.

- Holds the company's provider keys; clients never see them.
- Accepts only an agent session token, and only from sandbox egress addresses. The
  session token is injected into the sandbox as an OpenShell provider credential and is
  never given to developer machines, so an agent running anywhere else has no model access.
- Never forwards client credentials upstream. That includes a personal claude.ai login,
  which Claude Code sends when ANTHROPIC_BASE_URL is set without a gateway credential.
- Relays request bodies byte-for-byte and streams responses unbuffered, as Claude Code
  requires. It reads `model` for the policy check and usage for metering, without
  changing either.
- Records one OCSF `llm.request` event per request (usage and metadata) and keeps every
  prompt and response body in the Policy API's encrypted content store (ADR 0001, D5). The
  prompt is stored before it is sent upstream; if it cannot be stored, the request is refused.
- The `local` provider is the company's self-hosted inference (GPU) servers. They accept only
  this gateway: it connects with a client certificate (mTLS), and no sandbox policy may name
  them. No API key is sent; the client's credentials are never forwarded.
- Applies the session policy's guardrails to every provider (ADR 0001, D3): prompts are checked
  before they are sent, responses as they stream (a violation ends the stream). A guardrail
  error refuses the request. Only an administrator's time-limited bypass, returned with the
  session by the Policy API, skips the guardrails; nothing else is ever skipped.
"""
import fnmatch
import hashlib
import ipaddress
import json
import os
import ssl
import time
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from . import guardrails as gr

app = FastAPI(title="Company LLM Gateway")

PROVIDERS = {
    "anthropic": {"upstream": ("ANTHROPIC_UPSTREAM", "https://api.anthropic.com"), "key": "ANTHROPIC_API_KEY",
                  "routes": {("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens"), ("GET", "/v1/models")}},
    "openai": {"upstream": ("OPENAI_UPSTREAM", "https://api.openai.com"), "key": "OPENAI_API_KEY",
               "routes": {("POST", "/v1/responses"), ("GET", "/v1/models")}},
    # Self-hosted OpenAI-compatible servers (vLLM, TGI, Triton). No key: mTLS identifies the gateway.
    "local": {"upstream": ("LOCAL_UPSTREAM", ""), "key": None,
              "routes": {("POST", "/v1/chat/completions"), ("POST", "/v1/completions"), ("GET", "/v1/models")}},
}
# Response headers Claude Code / Codex rely on (retries, stall detection, usage display).
FORWARD_RESPONSE = ("content-type", "retry-after", "x-should-retry", "request-id", "x-request-id")
FORWARD_RESPONSE_PREFIXES = ("anthropic-ratelimit-", "x-ratelimit-", "openai-")
SESSION_CACHE_SECONDS = 15

# Overridable in tests.
upstream_transport = None
policy_transport = None
_sessions: dict[str, tuple[float, dict]] = {}
_rate: dict[str, list[float]] = {}


def env(name, default=""):
    return os.environ.get(name, default)


def client_ip(request: Request) -> ipaddress._BaseAddress:
    """Caller address; X-Forwarded-For is honored only when the hop is a trusted proxy."""
    ip = ipaddress.ip_address(request.client.host if request.client else "0.0.0.0")
    trusted = [ipaddress.ip_network(c) for c in env("TRUSTED_PROXY_CIDRS").split(",") if c]
    if any(ip in n for n in trusted):
        for hop in reversed([h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]):
            ip = ipaddress.ip_address(hop)
            if not any(ip in n for n in trusted):
                break
    return ip


def check_source(request: Request):
    cidrs = [c for c in env("SANDBOX_EGRESS_CIDRS").split(",") if c]
    if not cidrs:
        if env("LLM_GATEWAY_ALLOW_ANY_SOURCE") == "1":  # local development only
            return
        raise HTTPException(500, "SANDBOX_EGRESS_CIDRS is not configured")
    if not any(client_ip(request) in ipaddress.ip_network(c) for c in cidrs):
        raise HTTPException(403, "model access is only available from managed sandboxes")


def session_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "").strip()
    if not token.startswith("ast_"):
        # Includes personal OAuth tokens and provider API keys: never accepted, never forwarded.
        raise HTTPException(401, "a company agent session token is required")
    return token


async def resolve_session(token: str) -> dict:
    key = hashlib.sha256(token.encode()).hexdigest()
    hit = _sessions.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    async with httpx.AsyncClient(timeout=5, transport=policy_transport) as c:
        r = await c.post(f"{env('POLICY_API', 'http://localhost:8080')}/v1/sessions/introspect", json={"session_token": token},
                         headers={"Authorization": f"Bearer {env('LLM_GATEWAY_TOKEN')}"})
    if r.status_code in (401, 403):
        _sessions.pop(key, None)
        raise HTTPException(r.status_code, r.json().get("detail", "session rejected"))
    r.raise_for_status()
    s = r.json()
    # Short cache: revocation reaches model access within SESSION_CACHE_SECONDS.
    _sessions[key] = (time.monotonic() + SESSION_CACHE_SECONDS, s)
    return s


def rate_limit(s: dict):
    limit = (s.get("llm") or {}).get("max_requests_per_minute")
    if not limit:
        return
    now = time.monotonic()
    window = [t for t in _rate.get(s["session_id"], []) if t > now - 60]
    if len(window) >= limit:
        raise HTTPException(429, "session request rate limit reached", headers={"retry-after": "10"})
    window.append(now)
    _rate[s["session_id"]] = window


def check_model(s: dict, provider: str, body: bytes):
    allowed = ((s.get("llm") or {}).get(provider) or {}).get("models") or []
    if not allowed:
        raise HTTPException(403, f"policy grants no {provider} model access")
    try:
        model = json.loads(body).get("model")
    except (ValueError, AttributeError):
        raise HTTPException(400, "request body must be a JSON object")
    if not isinstance(model, str) or not any(fnmatch.fnmatchcase(model, pat) for pat in allowed):
        raise HTTPException(403, f"model {model!r} is not allowed by policy")
    return model


def upstream_client(provider: str) -> httpx.AsyncClient:
    timeout = httpx.Timeout(600, connect=10)
    if provider != "local":
        return httpx.AsyncClient(timeout=timeout, transport=upstream_transport)
    upstream = env("LOCAL_UPSTREAM")
    if not upstream:
        raise HTTPException(500, "LOCAL_UPSTREAM is not configured")
    if not upstream.startswith("https://"):
        if env("LOCAL_ALLOW_PLAINTEXT") != "1":  # local development only
            raise HTTPException(500, "LOCAL_UPSTREAM must be https (mTLS)")
        return httpx.AsyncClient(timeout=timeout, transport=upstream_transport)
    if not (env("LOCAL_CLIENT_CERT") and env("LOCAL_CLIENT_KEY")):
        raise HTTPException(500, "LOCAL_CLIENT_CERT and LOCAL_CLIENT_KEY are required for the local inference backend")
    ctx = ssl.create_default_context(cafile=env("LOCAL_CA_BUNDLE") or None)
    ctx.load_cert_chain(env("LOCAL_CLIENT_CERT"), env("LOCAL_CLIENT_KEY"))
    return httpx.AsyncClient(timeout=timeout, transport=upstream_transport, verify=ctx)


def upstream_headers(provider: str, request: Request) -> dict:
    h = {"content-type": request.headers.get("content-type", "application/json"), "accept": request.headers.get("accept", "*/*"),
         # Identity encoding keeps relayed bytes readable for metering.
         "accept-encoding": "identity"}
    if provider == "anthropic":
        for k, v in request.headers.items():
            if k.lower().startswith("anthropic-") and k.lower() != "anthropic-beta":
                h[k.lower()] = v
        h.setdefault("anthropic-version", "2023-06-01")
        # Forward capability values verbatim, except OAuth: only the company key authenticates.
        beta = [b.strip() for b in request.headers.get("anthropic-beta", "").split(",") if b.strip() and not b.strip().startswith("oauth-")]
        if beta:
            h["anthropic-beta"] = ",".join(beta)
        h["x-api-key"] = env("ANTHROPIC_API_KEY")
    elif provider == "local":
        pass  # authenticated by the gateway's client certificate
    else:
        if request.headers.get("openai-beta"):
            h["openai-beta"] = request.headers["openai-beta"]
        h["authorization"] = f"Bearer {env('OPENAI_API_KEY')}"
    return h


class Meter:
    """Extracts token usage from JSON or SSE bodies as they stream past, without altering them."""

    def __init__(self, streaming: bool):
        self.streaming, self.buf, self.usage = streaming, b"", {}

    def feed(self, chunk: bytes):
        self.buf += chunk
        if not self.streaming:
            return
        *lines, self.buf = self.buf.split(b"\n")
        for line in lines:
            if line.startswith(b"data:"):
                self._event(line[5:].strip())

    def _event(self, data: bytes):
        try:
            e = json.loads(data)
        except ValueError:
            return
        t = e.get("type")
        if t == "message_start":
            self.usage.update(e.get("message", {}).get("usage") or {})
        elif t == "message_delta":
            self.usage.update(e.get("usage") or {})  # output_tokens is cumulative
        elif t == "response.completed":
            self.usage.update((e.get("response") or {}).get("usage") or {})
        elif t is None and isinstance(e.get("usage"), dict):
            # OpenAI-compatible chat/completions chunks (local servers): usage is on the last chunk.
            self.usage.update(e["usage"])

    def finish(self):
        if not self.streaming:
            try:
                self.usage = json.loads(self.buf).get("usage") or {}
            except (ValueError, AttributeError):
                pass
        return {k: v for k, v in self.usage.items() if isinstance(v, int)}


def content_limit() -> int:
    return int(env("CONTENT_MAX_BYTES", str(16 * 1024 * 1024)))


async def store_content(s: dict, request_id: str, direction: str, data: bytes, truncated: bool = False) -> bool:
    """Keep a prompt or response body in the Policy API's encrypted content store."""
    body = {"session_id": s["session_id"], "user_id": s["user_id"], "request_id": request_id, "direction": direction,
            "content": data.decode("utf-8", "replace"), "truncated": truncated}
    try:
        async with httpx.AsyncClient(timeout=10, transport=policy_transport) as c:
            r = await c.post(f"{env('POLICY_API', 'http://localhost:8080')}/v1/audit/content", json=body,
                             headers={"Authorization": f"Bearer {env('LLM_GATEWAY_TOKEN')}"})
        return r.status_code == 200
    except httpx.HTTPError:
        return False


async def report(s: dict, event_type: str, message: str, data: dict, success: bool = True):
    await post_event({"event_type": event_type, "session_id": s["session_id"], "user_id": s["user_id"], "device_id": s.get("device_id"),
                      "success": success, "message": message, "data": data})


async def audit(s: dict, provider: str, path: str, model, status: int, usage: dict, started: float, streaming: bool,
                request_id: str | None = None, content_stored: bool | None = None, guardrail: dict | None = None):
    await report(s, "llm.request", f"{provider} {path} {status}", success=status < 400,
                 data={"provider": provider, "path": path, "model": model, "status": status, "stream": streaming,
                       "usage": usage, "duration_ms": int((time.monotonic() - started) * 1000), "repo": s.get("repo"),
                       "request_id": request_id, "content_stored": content_stored, "guardrail": guardrail})


async def post_event(body: dict):
    try:
        async with httpx.AsyncClient(timeout=5, transport=policy_transport) as c:
            await c.post(f"{env('POLICY_API', 'http://localhost:8080')}/v1/audit/events", json=body,
                         headers={"Authorization": f"Bearer {env('LLM_GATEWAY_TOKEN')}"})
    except httpx.HTTPError:
        pass  # the gateway's own access log still has the request


def error_body(provider: str, kind: str, message: str) -> dict:
    if provider == "anthropic":
        return {"type": "error", "error": {"type": kind, "message": message}}
    return {"error": {"type": kind, "message": message}}


def active_bypass(s: dict, model) -> dict | None:
    """An administrator's guardrail bypass covering this request. The Policy API returns the ones
    that apply to the session; model-scoped ones are matched here. Expiry is checked against the
    clock, so a cached session never extends a bypass past its end."""
    now = datetime.now(timezone.utc)
    for b in s.get("guardrail_bypasses") or []:
        try:
            if datetime.fromisoformat(b["expires_at"]) <= now:
                continue
        except (KeyError, TypeError, ValueError):
            continue  # unreadable expiry: not a bypass
        if b.get("scope") != "model" or (isinstance(model, str) and fnmatch.fnmatchcase(model, b.get("target") or "")):
            return b
    return None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.head("/anthropic/api/hello")
def hello():
    # Claude Code connection-warming probe.
    return Response(status_code=200)


@app.api_route("/{provider}/{path:path}", methods=["GET", "POST"])
async def proxy(provider: str, path: str, request: Request):
    p = PROVIDERS.get(provider)
    path = "/" + path
    if not p or (request.method, path) not in p["routes"]:
        raise HTTPException(404, "not a gateway route")
    check_source(request)
    s = await resolve_session(session_token(request))
    rate_limit(s)
    body = await request.body()
    model = check_model(s, provider, body) if request.method == "POST" else None
    request_id = uuid.uuid4().hex
    bypass = active_bypass(s, model)
    guards = None if bypass else s.get("guardrails")
    guard_info = {"bypassed": bool(bypass), "bypass_id": (bypass or {}).get("id"), "blocked": None, "error": None}
    if request.method == "POST":
        if len(body) > content_limit():
            raise HTTPException(413, "request body exceeds the auditable size limit")
        # No audit, no inference: the prompt must be on record before it leaves the gateway.
        if not await store_content(s, request_id, "request", body):
            return JSONResponse({"type": "error", "error": {"type": "api_error", "message": "audit store unavailable; request refused"}}, status_code=503)
        try:
            gr.check_input(body, guards)
        except gr.Violation as v:
            await report(s, "guardrail.block", str(v), {"direction": "input", "rules": v.rules, "provider": provider, "model": model,
                                                        "request_id": request_id}, success=False)
            return JSONResponse(error_body(provider, "permission_error", f"request blocked by guardrail: {', '.join(v.rules)}"), status_code=403)
        except Exception as e:  # fail-closed: a broken guardrail never lets a prompt through
            await report(s, "guardrail.error", f"input guardrail failed: {type(e).__name__}",
                         {"direction": "input", "error": type(e).__name__, "provider": provider, "request_id": request_id}, success=False)
            return JSONResponse(error_body(provider, "api_error", "guardrail unavailable; request refused"), status_code=503)
    started = time.monotonic()
    client = upstream_client(provider)
    upstream = env(*p["upstream"]).rstrip("/")
    req = client.build_request(request.method, upstream + path, params=request.query_params, headers=upstream_headers(provider, request),
                               content=body if request.method == "POST" else None)
    try:
        r = await client.send(req, stream=True)
    except httpx.HTTPError as e:
        await client.aclose()
        return JSONResponse({"type": "error", "error": {"type": "api_error", "message": f"upstream unreachable: {e}"}}, status_code=502)
    headers = {k: v for k, v in r.headers.items() if k.lower() in FORWARD_RESPONSE or k.lower().startswith(FORWARD_RESPONSE_PREFIXES)}
    streaming = r.headers.get("content-type", "").startswith("text/event-stream")
    meter = Meter(streaming)
    captured, limit = bytearray(), content_limit()
    scanner = gr.OutputScanner(guards if request.method == "POST" else None, streaming)

    def capture(chunk: bytes):
        meter.feed(chunk)
        if len(captured) <= limit:
            captured.extend(chunk)

    async def output_failed(e: Exception):
        if isinstance(e, gr.Violation):
            guard_info["blocked"] = "output"
            await report(s, "guardrail.block", str(e), {"direction": "output", "rules": e.rules, "provider": provider, "model": model,
                                                        "request_id": request_id}, success=False)
            return f"response blocked by guardrail: {', '.join(e.rules)}"
        guard_info["error"] = type(e).__name__
        await report(s, "guardrail.error", f"output guardrail failed: {type(e).__name__}",
                     {"direction": "output", "error": type(e).__name__, "provider": provider, "request_id": request_id}, success=False)
        return "guardrail unavailable; response stopped"

    async def relay():
        # Only guardrail calls are guarded here: an upstream stream error is not a guardrail failure.
        chunks = r.aiter_raw()
        while True:
            chunk = await anext(chunks, None)
            try:
                if chunk is None:
                    out = scanner.finish()
                else:
                    capture(chunk)
                    out = scanner.feed(chunk)
            except Exception as e:  # violation or guardrail failure: end the stream (fail-closed)
                if isinstance(e, gr.Violation) and e.safe:
                    yield e.safe
                yield gr.stream_error(provider, await output_failed(e))
                return
            if out:
                yield out
            if chunk is None:
                return

    async def done():
        await r.aclose()
        await client.aclose()
        if request.method == "POST":
            # The response is already with the client; a failed store is flagged for the SIEM.
            stored = await store_content(s, request_id, "response", bytes(captured[:limit]), truncated=len(captured) > limit)
            await audit(s, provider, path, model, r.status_code, meter.finish(), started, streaming, request_id, stored, guard_info)

    if request.method == "GET" and path == "/v1/models" and r.status_code == 200:
        # Only list what the session may use.
        data = json.loads(await r.aread())
        await done()
        allowed = ((s.get("llm") or {}).get(provider) or {}).get("models") or []
        data["data"] = [m for m in data.get("data", []) if any(fnmatch.fnmatchcase(m.get("id", ""), pat) for pat in allowed)]
        return JSONResponse(data, headers={k: v for k, v in headers.items() if k.lower() != "content-type"})
    if scanner.active and not streaming:
        # A whole JSON response is checked before any of it is sent.
        data = await r.aread()
        capture(data)
        status = r.status_code
        try:
            scanner.feed(data)
            data = scanner.finish()
        except Exception as e:
            message = await output_failed(e)
            blocked = isinstance(e, gr.Violation)
            data, status = json.dumps(error_body(provider, "permission_error" if blocked else "api_error", message)).encode(), 403 if blocked else 503
        await done()
        return Response(data, status_code=status, headers=headers)
    return StreamingResponse(relay(), status_code=r.status_code, headers=headers, background=BackgroundTask(done))
