import json
import os
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import orchestrator.main as o
from orchestrator.openshell import OpenShell

FAKE = str(Path(__file__).parent / "fake_openshell.py")
SANDBOX_IMAGE = "registry.company.internal/tether/sandbox-agent:1.0@sha256:" + "a" * 64
LOCAL_AGENT_IMAGE = "registry.company.internal/tether/sandbox-local-agent:0.1.0@sha256:" + "b" * 64
USER = {"Authorization": "Bearer dev:kim"}
BASE_SESSION = {"session_id": "sid-1", "session_token": "ast_SECRET_SESSION", "user_id": "kim", "device_id": "mac-1",
                "sandbox_name": "agent-kim-abc-def", "policy_version": 3, "openshell_policy": {"version": 1, "network_policies": {}},
                "policy": {"github": {"org": "acme", "permissions": {"contents": "write"}}, "aws": {"role": "arn:aws:iam::123456789012:role/R"}},
                "providers": {"agent-kim-abc-def-llm": "tether-llm", "agent-kim-abc-def-policy": "tether-policy",
                              "agent-kim-abc-def-aws": "tether-aws", "agent-kim-abc-def-github": "github-org"}}


class World:
    def __init__(self, monkeypatch, tmp_path, session=None, policy_status=200):
        self.session, self.policy_status = dict(session or BASE_SESSION), policy_status
        self.requests, self.audits, self.revoke_body = [], [], None
        (tmp_path / "state").mkdir()
        self.log = tmp_path / "log.jsonl"
        monkeypatch.setenv("FAKE_STATE", str(tmp_path / "state"))
        monkeypatch.setenv("FAKE_LOG", str(self.log))
        monkeypatch.setenv("GITHUB_ORG", "acme")
        monkeypatch.setenv("ORCHESTRATOR_TOKEN", "orch-secret")
        monkeypatch.setenv("LLM_GATEWAY_URL", "https://llm.company.internal")
        monkeypatch.setenv("ORCHESTRATOR_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SANDBOX_IMAGE", SANDBOX_IMAGE)
        monkeypatch.setenv("LOCAL_AGENT_IMAGE", LOCAL_AGENT_IMAGE)
        monkeypatch.setattr(o, "openshell", OpenShell(FAKE))
        monkeypatch.setattr(o, "http_transport", httpx.MockTransport(self.handle))
        o.state.tickets.clear(); o.state.relays.clear()

    def handle(self, req):
        self.requests.append(req)
        body = json.loads(req.content) if req.content else {}
        p = req.url.path
        if p == "/v1/agent/sessions":
            assert req.headers["authorization"] == "Bearer orch-secret"
            self.session_request = body
            if self.policy_status != 200:
                return httpx.Response(self.policy_status, json={"detail": "no policy allows claude"})
            return httpx.Response(200, json=self.session)
        if p == "/v1/credentials/aws":
            assert req.headers["authorization"] == USER["Authorization"]
            return httpx.Response(200, json={"AccessKeyId": "AK", "SecretAccessKey": "AWSVALUE-9x", "SessionToken": "ST", "Expiration": "x"})
        if p == "/v1/credentials/github":
            return httpx.Response(200, json={"token": "ghs_SECRET", "expires_at": "x"})
        if p == "/v1/audit/events":
            assert req.headers["authorization"] == "Bearer orch-secret"
            self.audits.append(body)
            return httpx.Response(200, json={"accepted": True})
        if p == "/v1/admin/sessions/revoke":
            if req.headers["authorization"] != "Bearer dev:secops":
                return httpx.Response(403, json={"detail": "user credentials cannot call this endpoint"})
            return httpx.Response(200, json={"revoked": 1, "sessions": [{"session_id": "sid-1", "user_id": "kim", "device_id": "mac-1", "sandbox_name": "agent-kim-abc-def"}]})
        if p == "/v1/admin/revoke":
            self.revoke_body = body
            return httpx.Response(200, json={"aws_sessions_denied": 1, "github_tokens_revoked": 1})
        return httpx.Response(404)

    def calls(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []


client = TestClient(o.app)
LAUNCH = {"agent": "claude", "repo": "git@github.com:acme/payments.git", "device_id": "mac-1"}


def launch(headers=USER, **body):
    return client.post("/v1/launch", headers=headers, json={**LAUNCH, **body})


def test_launch_creates_sandbox_with_bound_providers(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    r = launch()
    assert r.status_code == 200, r.text
    assert "session_token" not in r.text and "ast_SECRET" not in r.text  # developers never see it
    assert w.session_request["user_token"] == "dev:kim" and w.session_request["device_verified"] is False
    calls = w.calls()
    creates = {c["argv"][c["argv"].index("--name") + 1]: c for c in calls if c["argv"][:2] == ["provider", "create"]}
    assert {n: c["argv"][c["argv"].index("--type") + 1] for n, c in creates.items()} == {
        "agent-kim-abc-def-llm": "tether-llm", "agent-kim-abc-def-policy": "tether-policy",
        "agent-kim-abc-def-aws": "tether-aws", "agent-kim-abc-def-github": "github-org"}
    assert creates["agent-kim-abc-def-llm"]["env"]["ANTHROPIC_AUTH_TOKEN"] == "ast_SECRET_SESSION"
    assert creates["agent-kim-abc-def-github"]["env"]["GITHUB_TOKEN"] == "ghs_SECRET"
    argv_text = json.dumps([c["argv"] for c in calls])
    for secret in ("ast_SECRET_SESSION", "ghs_SECRET", "AWSVALUE-9x"):
        assert secret not in argv_text
    sandbox = next(c["argv"] for c in calls if c["argv"][:2] == ["sandbox", "create"])
    assert sandbox.count("--provider") == 4 and "managed-by=tether-orchestrator" in sandbox
    # OpenShell v0.1.9: create has no --workdir (the image WORKDIR is the workspace); the image is explicit.
    assert "--workdir" not in sandbox and sandbox[sandbox.index("--from") + 1] == SANDBOX_IMAGE
    assert "--detach" in sandbox and "--no-auto-providers" in sandbox
    clone = next(c["argv"] for c in calls if "clone" in c["argv"])
    assert "--no-login-shell" in clone and "--no-tty" in clone
    assert clone[-2:] == ["https://github.com/acme/payments.git", "/workspace/payments"]
    assert [a["event_type"] for a in w.audits] == ["sandbox.create"]
    assert not list(tmp_path.glob("*.yaml"))  # policy temp file removed


def test_reuse_refreshes_providers_and_sets_network_policy(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    launch()
    open(tmp_path / "log.jsonl", "w").close()
    for kind in ("provider-agent-kim-abc-def-llm",):
        assert (tmp_path / "state" / kind).exists()
    assert launch().status_code == 200
    cmds = [c["argv"][:2] for c in w.calls()]
    assert ["provider", "update"] in cmds and ["policy", "set"] in cmds
    assert ["sandbox", "create"] not in cmds and not any("clone" in c["argv"] for c in w.calls())
    assert w.audits[-1]["event_type"] == "sandbox.reuse"


@pytest.mark.parametrize("repo", ["git@github.com:other/x.git", "https://github.com/acme-evil/x", "/Users/kim/src/x", "git@gitlab.com:acme/x.git",
                                  "https://github.com/acme/../x"])
def test_only_repositories_in_org(monkeypatch, tmp_path, repo):
    w = World(monkeypatch, tmp_path)
    assert launch(repo=repo).status_code == 403
    assert w.requests == [] and w.calls() == []


@pytest.mark.parametrize("image", ["", "registry.company.internal/tether/sandbox-agent:latest", "sandbox-agent@sha256:abc"])
def test_sandbox_image_must_be_configured_and_digest_pinned(monkeypatch, tmp_path, image):
    w = World(monkeypatch, tmp_path)
    monkeypatch.setenv("SANDBOX_IMAGE", image)
    r = launch()
    assert r.status_code == 500 and "SANDBOX_IMAGE must be a digest-pinned" in r.json()["detail"]
    assert w.calls() == []


def test_policy_rejection_passes_through(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path, policy_status=403)
    r = launch()
    assert r.status_code == 403 and "no policy" in r.json()["detail"] and w.calls() == []


def test_policy_org_mismatch_fails_closed(monkeypatch, tmp_path):
    s = {**BASE_SESSION, "policy": {**BASE_SESSION["policy"], "github": {"org": "other", "permissions": {"contents": "read"}}}}
    w = World(monkeypatch, tmp_path, session=s)
    assert launch().status_code == 500 and w.calls() == []


def test_device_from_mtls_header_only(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    monkeypatch.setenv("DEVICE_ID_HEADER", "X-Client-Cert-Fingerprint")
    assert launch().status_code == 401
    assert launch(headers={**USER, "X-Client-Cert-Fingerprint": "sha256:dev"}).status_code == 200
    assert (w.session_request["device_id"], w.session_request["device_verified"]) == ("sha256:dev", True)


def test_clone_failure_reported(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    monkeypatch.setenv("FAKE_CLONE_RC", "128")
    assert launch().status_code == 502
    assert w.audits[-1]["event_type"] == "sandbox.create" and w.audits[-1]["success"] is False


def test_live_policy_rejection_blocks_launch(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    launch()
    monkeypatch.setenv("FAKE_POLICY_RC", "1")
    r = launch()
    assert r.status_code == 502 and "network policy rejected" in r.json()["detail"]


# --- terminal relay ------------------------------------------------------------

def test_attach_relays_a_real_pty(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    ticket = launch().json()["ticket"]
    with client.websocket_connect(f"/v1/attach?ticket={ticket}&rows=40&cols=120") as ws:
        out = b""
        while b"base=" not in out:
            out += ws.receive_bytes()
        assert b"agent=claude tty=True size=120x40 base=https://llm.company.internal/anthropic" in out
        ws.send_bytes(b"hello\n")
        while True:
            msg = ws.receive()
            if msg.get("bytes"):
                out += msg["bytes"]
            elif msg.get("text"):
                assert json.loads(msg["text"]) == {"type": "exit", "code": 3}
                break
    assert b"got:hello" in out
    assert w.audits[-1]["event_type"] == "agent.exit" and w.audits[-1]["data"]["returncode"] == 3
    tty_exec = next(c["argv"] for c in w.calls() if "--tty" in c["argv"])
    assert tty_exec[tty_exec.index("--workdir") + 1] == "/workspace/payments"
    assert "--no-login-shell" not in tty_exec  # the interactive agent keeps the image's login environment


def test_ticket_is_single_use_and_required(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path)
    ticket = launch().json()["ticket"]
    o.state.tickets[ticket].expires = 0
    from starlette.websockets import WebSocketDisconnect
    for t in (ticket, "forged"):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/v1/attach?ticket={t}") as ws:
                ws.receive_bytes()


# --- kill switch -----------------------------------------------------------------

def test_admin_revoke_tears_everything_down(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    launch()
    assert (tmp_path / "state" / "sandbox-agent-kim-abc-def").exists()
    r = client.post("/v1/admin/revoke", headers={"Authorization": "Bearer dev:secops"}, json={"user_id": "kim", "reason": "INC-9"})
    assert r.status_code == 200, r.text
    assert r.json()["sandboxes_deleted"] == ["agent-kim-abc-def"]
    assert not (tmp_path / "state" / "sandbox-agent-kim-abc-def").exists()
    assert w.revoke_body == {"session_ids": ["sid-1"], "reason": "INC-9"}
    assert [a["event_type"] for a in w.audits][-1] == "sandbox.delete"
    assert not o.state.tickets


def test_admin_revoke_needs_admin(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    r = client.post("/v1/admin/revoke", headers=USER, json={"all": True, "reason": "x"})
    assert r.status_code == 403 and w.revoke_body is None


def test_missing_openshell_cli_is_a_clean_error(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path)
    monkeypatch.setattr(o, "openshell", OpenShell("/nonexistent/openshell"))
    r = launch()
    assert r.status_code == 502 and "cannot run" in r.json()["detail"]


def test_agents_reach_only_the_gateway_and_keep_state_in_tmp():
    from orchestrator.agents import agent_command
    argv, e = agent_command("claude", "https://gw.example")
    assert argv[:2] == ["sh", "-c"] and 'exec "$0" "$@"' in argv[2] and argv[3:] == ["claude"] and e["ANTHROPIC_BASE_URL"] == "https://gw.example/anthropic"
    assert e["CLAUDE_CONFIG_DIR"].startswith("/tmp/") and e["CODEX_HOME"].startswith("/tmp/")
    argv, e = agent_command("codex", "https://gw.example")
    config = [argv[i + 1] for i, a in enumerate(argv) if a == "-c"]
    assert argv[3] == "codex" and 'model_provider="tether"' in config
    assert 'model_providers.tether.base_url="https://gw.example/openai/v1"' in config
    # The placeholder the tether-llm provider injects; no real key is ever in the sandbox.
    assert 'model_providers.tether.env_key="TETHER_LLM_TOKEN"' in config
    assert not any(k.endswith("API_KEY") for k in e)
