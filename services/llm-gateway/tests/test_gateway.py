import json

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.main as g

def resp(status, content=b"", headers=None, json_body=None):
    """Upstream response with a real (unread) byte stream, like a network transport returns."""
    if json_body is not None:
        content, headers = json.dumps(json_body).encode(), {"content-type": "application/json", **(headers or {})}
    return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(content))


SESSION = {"session_id": "sid-1", "user_id": "kim", "device_id": "mac-1", "repo": "github.com/co/r",
           "llm": {"anthropic": {"models": ["claude-opus-5-5", "claude-haiku-*"]}, "openai": {"models": ["gpt-5*"]}, "max_requests_per_minute": 5}}
TOKEN = {"Authorization": "Bearer ast_good"}
SSE = (b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":12,"cache_read_input_tokens":3,"output_tokens":1}}}\n\n'
       b'event: ping\ndata: {"type":"ping"}\n\n'
       b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}\n\n'
       b'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}\n\n'
       b'event: message_stop\ndata: {"type":"message_stop"}\n\n')


class World:
    def __init__(self, monkeypatch, session=SESSION, introspect_status=200):
        self.upstream, self.audits, self.contents, self.introspects = [], [], [], 0
        self.content_status = 200
        self.session, self.introspect_status = session, introspect_status
        self.upstream_response = lambda req: resp(200, SSE, {"content-type": "text/event-stream", "request-id": "req_1",
                                                           "anthropic-ratelimit-unified-status": "allowed", "set-cookie": "x=1"})
        monkeypatch.setattr(g, "upstream_transport", httpx.MockTransport(self.handle_upstream))
        monkeypatch.setattr(g, "policy_transport", httpx.MockTransport(self.handle_policy))
        monkeypatch.setenv("SANDBOX_EGRESS_CIDRS", "10.20.0.0/16")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-company")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-company")
        monkeypatch.setenv("LLM_GATEWAY_TOKEN", "gw-secret")
        g._sessions.clear(); g._rate.clear()

    def handle_upstream(self, req):
        self.upstream.append(req)
        return self.upstream_response(req)

    def handle_policy(self, req):
        assert req.headers["authorization"] == "Bearer gw-secret"
        if req.url.path == "/v1/sessions/introspect":
            self.introspects += 1
            if json.loads(req.content)["session_token"] != "ast_good" or self.introspect_status != 200:
                return httpx.Response(401, json={"detail": "invalid or expired session token"})
            return httpx.Response(200, json=self.session)
        if req.url.path == "/v1/audit/content":
            if self.content_status != 200:
                return httpx.Response(self.content_status, json={"detail": "unavailable"})
            self.contents.append(json.loads(req.content))
            return httpx.Response(200, json={"content_id": f"c{len(self.contents)}", "sha256": "x"})
        self.audits.append(json.loads(req.content))
        return httpx.Response(200, json={"accepted": True})


def client(ip="10.20.3.4"):
    return TestClient(g.app, client=(ip, 5000))


BODY = json.dumps({"model": "claude-opus-5-5", "max_tokens": 10, "stream": True, "messages": [{"role": "user", "content": "PROMPT-MARKER-7f3a"}]}).encode()


def post(c, path="/anthropic/v1/messages", body=BODY, headers=None):
    return c.post(path, content=body, headers={"content-type": "application/json", "anthropic-version": "2023-06-01", **(TOKEN if headers is None else headers)})


def test_streams_byte_for_byte_with_company_key(monkeypatch):
    w = World(monkeypatch)
    r = post(client(), headers={**TOKEN, "anthropic-beta": "context-management-2025-06-27,oauth-2025-04-20, extended-cache-ttl-2025-04-11",
                                "x-claude-code-session-id": "cc-1", "cookie": "a=b"})
    assert r.status_code == 200 and r.content == SSE
    assert r.headers["content-type"].startswith("text/event-stream") and r.headers["request-id"] == "req_1"
    assert "set-cookie" not in r.headers
    up = w.upstream[0]
    assert up.url == "https://api.anthropic.com/v1/messages" and up.content == BODY
    assert up.headers["x-api-key"] == "sk-ant-company" and "authorization" not in up.headers
    assert up.headers["anthropic-beta"] == "context-management-2025-06-27,extended-cache-ttl-2025-04-11"  # oauth value dropped
    assert "cookie" not in up.headers and "x-claude-code-session-id" not in up.headers


def test_usage_metered_and_content_kept_out_of_the_event(monkeypatch):
    w = World(monkeypatch)
    post(client())
    e = w.audits[-1]
    assert e["event_type"] == "llm.request" and e["user_id"] == "kim" and e["session_id"] == "sid-1"
    assert e["data"]["usage"] == {"input_tokens": 12, "cache_read_input_tokens": 3, "output_tokens": 7}
    assert e["data"]["model"] == "claude-opus-5-5" and e["data"]["stream"] is True
    # Bodies go to the encrypted content store (ADR 0001, D5), never into the OCSF event itself.
    assert "PROMPT-MARKER-7f3a" not in json.dumps(e)
    req, res = w.contents
    assert (req["direction"], res["direction"]) == ("request", "response")
    assert req["content"] == BODY.decode() and res["content"] == SSE.decode() and res["truncated"] is False
    assert req["request_id"] == res["request_id"] == e["data"]["request_id"] and e["data"]["content_stored"] is True
    assert req["session_id"] == "sid-1" and req["user_id"] == "kim"


@pytest.mark.parametrize("status", [503, 500, 404])
def test_no_inference_without_stored_prompt(monkeypatch, status):
    w = World(monkeypatch)
    w.content_status = status
    r = post(client())
    assert r.status_code == 503 and w.upstream == []


def test_oversized_prompt_refused_and_response_truncated(monkeypatch):
    w = World(monkeypatch)
    monkeypatch.setenv("CONTENT_MAX_BYTES", str(len(BODY)))
    assert post(client()).status_code == 200
    res = w.contents[-1]
    assert res["truncated"] is True and len(res["content"]) == len(BODY)
    monkeypatch.setenv("CONTENT_MAX_BYTES", str(len(BODY) - 1))
    n = len(w.upstream)
    assert post(client()).status_code == 413 and len(w.upstream) == n


def test_response_store_failure_is_flagged(monkeypatch):
    w = World(monkeypatch)
    calls = []
    orig = w.handle_policy

    def flaky(req):
        if req.url.path == "/v1/audit/content":
            calls.append(1)
            if len(calls) == 2:
                return httpx.Response(503, json={"detail": "down"})
        return orig(req)
    monkeypatch.setattr(g, "policy_transport", httpx.MockTransport(flaky))
    assert post(client()).status_code == 200
    assert w.audits[-1]["data"]["content_stored"] is False


@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer sk-ant-oat01-personal-claude-ai-login"},  # personal OAuth login
    {"x-api-key": "sk-ant-api03-personal-key"},
    {"Authorization": "Bearer ast_revoked"},
])
def test_only_session_tokens_accepted(monkeypatch, headers):
    w = World(monkeypatch)
    r = post(client(), headers=headers)
    assert r.status_code == 401 and w.upstream == []


def test_session_token_via_x_api_key(monkeypatch):
    World(monkeypatch)
    assert post(client(), headers={"x-api-key": "ast_good"}).status_code == 200


@pytest.mark.parametrize("ip", ["192.168.1.10", "10.21.0.1", "127.0.0.1"])
def test_only_from_sandbox_egress(monkeypatch, ip):
    w = World(monkeypatch)
    r = post(client(ip))
    assert r.status_code == 403 and w.upstream == [] and w.introspects == 0


def test_forwarded_for_only_from_trusted_proxy(monkeypatch):
    w = World(monkeypatch)
    spoof = {**TOKEN, "x-forwarded-for": "10.20.3.4"}
    assert post(client("192.168.1.10"), headers=spoof).status_code == 403
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "172.16.0.0/12")
    assert post(client("172.16.0.2"), headers={**TOKEN, "x-forwarded-for": "10.20.3.4"}).status_code == 200
    assert post(client("172.16.0.2"), headers={**TOKEN, "x-forwarded-for": "10.20.3.4, 192.168.1.10"}).status_code == 403


def test_unconfigured_source_fails_closed(monkeypatch):
    World(monkeypatch)
    monkeypatch.delenv("SANDBOX_EGRESS_CIDRS")
    assert post(client()).status_code == 500


@pytest.mark.parametrize("model,status", [("claude-opus-5-5", 200), ("claude-haiku-4-5", 200), ("claude-fable-5-1", 403), (None, 403)])
def test_model_allowlist(monkeypatch, model, status):
    World(monkeypatch)
    assert post(client(), body=json.dumps({"model": model, "max_tokens": 5, "messages": []}).encode()).status_code == status


def test_count_tokens_and_models_listing(monkeypatch):
    w = World(monkeypatch)
    w.upstream_response = lambda req: resp(200, json_body={"input_tokens": 42}) if req.method == "POST" else \
        resp(200, json_body={"data": [{"id": "claude-opus-5-5"}, {"id": "claude-fable-5-1"}, {"id": "claude-haiku-4-5"}]})
    assert post(client(), path="/anthropic/v1/messages/count_tokens", body=json.dumps({"model": "claude-opus-5-5", "messages": []}).encode()).json() == {"input_tokens": 42}
    ids = [m["id"] for m in client().get("/anthropic/v1/models?limit=1000", headers=TOKEN).json()["data"]]
    assert ids == ["claude-opus-5-5", "claude-haiku-4-5"]


def test_unknown_routes_rejected(monkeypatch):
    w = World(monkeypatch)
    for path in ("/anthropic/v1/organizations/users", "/anthropic/v1/files", "/openai/v1/chat/completions", "/gemini/v1/x"):
        assert post(client(), path=path).status_code == 404
    assert w.upstream == []


def test_openai_responses_with_bearer_key(monkeypatch):
    w = World(monkeypatch)
    stream = b'event: response.completed\ndata: {"type":"response.completed","response":{"usage":{"input_tokens":5,"output_tokens":9,"total_tokens":14}}}\n\n'
    w.upstream_response = lambda req: resp(200, stream, {"content-type": "text/event-stream"})
    r = post(client(), path="/openai/v1/responses", body=json.dumps({"model": "gpt-5-codex", "input": "x", "stream": True}).encode())
    assert r.status_code == 200 and r.content == stream
    assert w.upstream[0].headers["authorization"] == "Bearer sk-openai-company" and "x-api-key" not in w.upstream[0].headers
    assert w.audits[-1]["data"]["usage"] == {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}


def test_upstream_errors_forwarded_unmodified(monkeypatch):
    w = World(monkeypatch)
    err = b'{"type":"error","error":{"type":"invalid_request_error","message":"context_management: Extra inputs are not permitted"}}'
    w.upstream_response = lambda req: resp(400, err, {"content-type": "application/json", "x-should-retry": "false"})
    r = post(client())
    assert r.status_code == 400 and r.content == err and r.headers["x-should-retry"] == "false"
    assert w.audits[-1]["success"] is False


def test_rate_limit_per_session(monkeypatch):
    World(monkeypatch)
    c = client()
    codes = [post(c).status_code for _ in range(6)]
    assert codes == [200] * 5 + [429]


def test_revocation_reaches_gateway_after_cache(monkeypatch):
    w = World(monkeypatch)
    c = client()
    assert post(c).status_code == 200
    w.introspect_status = 401
    assert post(c).status_code == 200  # cached
    g._sessions.clear()  # cache expiry
    assert post(c).status_code == 401


def test_policy_without_llm_grant(monkeypatch):
    World(monkeypatch, session={**SESSION, "llm": {}})
    assert post(client()).status_code == 403


# --- local (self-hosted GPU) provider ---------------------------------------------------

LOCAL_SESSION = {**SESSION, "llm": {**SESSION["llm"], "local": {"models": ["company-coder-*"]}}}
LOCAL_BODY = json.dumps({"model": "company-coder-32b", "stream": True, "messages": [{"role": "user", "content": "hi"}]}).encode()
LOCAL_SSE = (b'data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"he"}}]}\n\n'
             b'data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"llo"}}]}\n\n'
             b'data: {"id":"c1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}\n\n'
             b'data: [DONE]\n\n')


def local_world(monkeypatch, session=LOCAL_SESSION):
    w = World(monkeypatch, session=session)
    monkeypatch.setenv("LOCAL_UPSTREAM", "http://vllm.gpu.internal:8000")
    monkeypatch.setenv("LOCAL_ALLOW_PLAINTEXT", "1")
    w.upstream_response = lambda req: resp(200, LOCAL_SSE, {"content-type": "text/event-stream"})
    return w


def local_post(c, body=LOCAL_BODY, headers=None):
    return c.post("/local/v1/chat/completions", content=body,
                  headers={"content-type": "application/json", **(headers or TOKEN)})


def test_local_streams_without_any_credential_upstream(monkeypatch):
    w = local_world(monkeypatch)
    r = local_post(client())
    assert r.status_code == 200 and r.content == LOCAL_SSE
    up = w.upstream[0]
    assert up.url == "http://vllm.gpu.internal:8000/v1/chat/completions" and up.content == LOCAL_BODY
    assert "authorization" not in up.headers and "x-api-key" not in up.headers  # session token never forwarded
    e = w.audits[-1]
    assert e["data"]["provider"] == "local" and e["data"]["usage"] == {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11}


@pytest.mark.parametrize("model", ["claude-opus-5-5", "gpt-5", "other-local"])
def test_local_model_allowlist(monkeypatch, model):
    w = local_world(monkeypatch)
    r = local_post(client(), body=json.dumps({"model": model, "messages": []}).encode())
    assert r.status_code == 403 and w.upstream == []


def test_local_needs_a_local_grant(monkeypatch):
    w = local_world(monkeypatch, session=SESSION)
    assert local_post(client()).status_code == 403 and w.upstream == []


def test_local_only_from_sandbox_egress(monkeypatch):
    w = local_world(monkeypatch)
    assert local_post(client("192.168.1.10")).status_code == 403 and w.upstream == []


@pytest.mark.parametrize("env", [
    {"LOCAL_UPSTREAM": ""},                                                   # not configured
    {"LOCAL_ALLOW_PLAINTEXT": ""},                                            # plaintext outside development
    {"LOCAL_UPSTREAM": "https://vllm.gpu.internal", "LOCAL_CLIENT_CERT": ""},  # https without a client certificate
])
def test_local_misconfiguration_fails_closed(monkeypatch, env):
    w = local_world(monkeypatch)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert local_post(client()).status_code == 500 and w.upstream == []


def test_local_unknown_route(monkeypatch):
    w = local_world(monkeypatch)
    r = client().post("/local/v1/embeddings", content=LOCAL_BODY, headers={"content-type": "application/json", **TOKEN})
    assert r.status_code == 404 and w.upstream == []


# --- guardrails (ADR 0001, D3) and break-glass (D4) -----------------------------------

from datetime import datetime, timedelta, timezone

from gateway import guardrails as gr

AWS = "AKIAIOSFODNN7EXAMPLE"
GUARDS = {"input": {"secrets": True}, "output": {"secrets": True}}
GUARDED = {**SESSION, "guardrails": GUARDS}


def leak_body():
    return json.dumps({"model": "claude-opus-5-5", "max_tokens": 5, "stream": True, "messages": [{"role": "user", "content": f"deploy with {AWS}"}]}).encode()


def bypass(minutes=10, **kw):
    return {"id": "bp-1", "scope": "all", "target": None,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(), **kw}


def events(w, kind):
    return [e for e in w.audits if e["event_type"] == kind]


def test_clean_request_streams_unchanged_under_guardrails(monkeypatch):
    w = World(monkeypatch, session=GUARDED)
    r = post(client())
    assert r.status_code == 200 and r.content == SSE
    assert events(w, "llm.request")[-1]["data"]["guardrail"] == {"bypassed": False, "bypass_id": None, "blocked": None, "error": None}


def test_input_violation_blocked_before_upstream_with_evidence(monkeypatch):
    w = World(monkeypatch, session=GUARDED)
    r = post(client(), body=leak_body())
    assert r.status_code == 403 and w.upstream == []
    assert "secrets.aws_access_key" in r.json()["error"]["message"]
    assert AWS in w.contents[0]["content"]  # the blocked prompt is on record
    e = events(w, "guardrail.block")[-1]
    assert e["data"]["direction"] == "input" and e["data"]["request_id"] == w.contents[0]["request_id"]
    assert AWS not in json.dumps(e)


def test_output_violation_ends_the_stream(monkeypatch):
    w = World(monkeypatch, session=GUARDED)
    clean = b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":3}}}\n\n'
    leak = b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"' + AWS.encode() + b'"}}\n\n'
    after = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    w.upstream_response = lambda req: resp(200, clean + leak + after, {"content-type": "text/event-stream"})
    r = post(client())
    assert r.content.startswith(clean) and AWS.encode() not in r.content and after not in r.content
    assert b"event: error" in r.content and b"secrets.aws_access_key" in r.content
    assert events(w, "guardrail.block")[-1]["data"]["direction"] == "output"
    assert events(w, "llm.request")[-1]["data"]["guardrail"]["blocked"] == "output"
    assert AWS in w.contents[-1]["content"]  # what the model produced is still audited


def test_non_streaming_output_violation_is_never_sent(monkeypatch):
    w = World(monkeypatch, session=GUARDED)
    w.upstream_response = lambda req: resp(200, json_body={"content": [{"type": "text", "text": AWS}], "usage": {"output_tokens": 4}})
    r = post(client(), body=json.dumps({"model": "claude-opus-5-5", "max_tokens": 5, "messages": []}).encode())
    assert r.status_code == 403 and AWS not in r.text
    assert events(w, "llm.request")[-1]["data"]["usage"] == {"output_tokens": 4}


def test_guardrail_failure_is_fail_closed(monkeypatch):
    w = World(monkeypatch, session=GUARDED)

    def broken(*a, **k):
        raise RuntimeError("model server down")
    monkeypatch.setattr(gr, "check_input", broken)
    r = post(client())
    assert r.status_code == 503 and w.upstream == []
    assert events(w, "guardrail.error")[-1]["data"]["error"] == "RuntimeError"


def test_output_guardrail_failure_cuts_the_stream(monkeypatch):
    w = World(monkeypatch, session=GUARDED)
    monkeypatch.setattr(gr.OutputScanner, "_check", lambda self, text: (_ for _ in ()).throw(RuntimeError("boom")))
    r = post(client())
    assert b"event: error" in r.content and b"guardrail unavailable" in r.content
    assert events(w, "llm.request")[-1]["data"]["guardrail"]["error"] == "RuntimeError"


def test_bypass_skips_guardrails_only(monkeypatch):
    w = World(monkeypatch, session={**GUARDED, "guardrail_bypasses": [bypass()]})
    r = post(client(), body=leak_body())
    assert r.status_code == 200
    e = events(w, "llm.request")[-1]["data"]
    assert e["guardrail"]["bypassed"] is True and e["guardrail"]["bypass_id"] == "bp-1"
    assert AWS in w.contents[0]["content"] and e["content_stored"] is True  # audit is never bypassed
    assert post(client(), body=json.dumps({"model": "claude-fable-5-1", "messages": []}).encode()).status_code == 403  # nor the model allow-list


def test_bypass_does_not_skip_source_or_session_checks(monkeypatch):
    w = World(monkeypatch, session={**GUARDED, "guardrail_bypasses": [bypass()]})
    assert post(client("192.168.1.10"), body=leak_body()).status_code == 403
    assert post(client(), body=leak_body(), headers={"Authorization": "Bearer sk-ant-personal"}).status_code == 401
    assert w.upstream == []


@pytest.mark.parametrize("b", [
    bypass(minutes=-1),                                   # expired, even if the session cache still lists it
    bypass(scope="model", target="claude-haiku-*"),       # bypass for another model
    {"id": "x", "scope": "all", "expires_at": "garbage"},  # unreadable: not a bypass
])
def test_bypass_that_does_not_apply(monkeypatch, b):
    w = World(monkeypatch, session={**GUARDED, "guardrail_bypasses": [b]})
    assert post(client(), body=leak_body()).status_code == 403 and w.upstream == []


def test_model_scoped_bypass(monkeypatch):
    World(monkeypatch, session={**GUARDED, "guardrail_bypasses": [bypass(scope="model", target="claude-opus-*")]})
    assert post(client(), body=leak_body()).status_code == 200


def test_upstream_stream_error_is_not_reported_as_a_guardrail_failure(monkeypatch):
    w = World(monkeypatch, session=GUARDED)

    class Broken(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield SSE[:40]
            raise httpx.ReadError("connection reset")
    w.upstream_response = lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=Broken())
    with pytest.raises(httpx.ReadError):
        post(client())
    assert events(w, "guardrail.error") == []
