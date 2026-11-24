import base64
import json
import os
import stat
import time

import httpx
import pytest
from click.testing import CliRunner

import tether_launcher.cli as cli

LAUNCH = {"session_id": "sid-1", "sandbox_name": "agent-kim-abc-def", "policy_version": 3, "ticket": "T1", "attach_path": "/v1/attach"}


class FakeWS:
    def __init__(self, messages):
        self.messages, self.sent, self.closed = list(messages), [], False

    def __iter__(self):
        for m in self.messages:
            if isinstance(m, Exception):
                raise m
            yield m

    def send(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class World:
    def __init__(self, monkeypatch, tmp_path, status=200, body=None, messages=(b"hello from sandbox\r\n", json.dumps({"type": "exit", "code": 0}))):
        self.requests, self.ws_urls = [], []
        self.ws = FakeWS(messages)
        self.status, self.body = status, body if body is not None else LAUNCH
        monkeypatch.setattr(cli, "HOME", tmp_path)
        monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "token.json")
        monkeypatch.setattr(cli, "MANAGED_CONFIG", tmp_path / "no-managed-config.json")
        monkeypatch.setenv("TETHER_TOKEN", "dev:kim")
        monkeypatch.setattr(cli, "http", lambda timeout=10: httpx.Client(transport=httpx.MockTransport(self.handle)))
        monkeypatch.setattr(cli, "ws_connect", lambda url: (self.ws_urls.append(url), self.ws)[1])
        monkeypatch.setattr(cli.subprocess, "check_output", lambda *a, **k: "/src/repo\n")
        monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "git@github.com:acme/payments.git\n", "returncode": 0})())
        self.unreachable = False

    def handle(self, req):
        if self.unreachable:
            raise httpx.ConnectError("refused")
        self.requests.append(req)
        return httpx.Response(self.status, json=self.body)


def invoke(*args):
    return CliRunner().invoke(cli.cli, list(args))


def test_launch_and_attach(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    r = invoke("claude")
    assert r.exit_code == 0, r.output
    req = w.requests[0]
    assert str(req.url) == "http://localhost:8083/v1/launch" and req.headers["authorization"] == "Bearer dev:kim"
    assert json.loads(req.content) == {"agent": "claude", "repo": "git@github.com:acme/payments.git", "environment": "development", "device_id": "local-dev"}
    assert w.ws_urls[0].startswith("ws://localhost:8083/v1/attach?ticket=T1&rows=") and w.ws.closed


def test_exit_code_propagates(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path, messages=[b"x", json.dumps({"type": "exit", "code": 7})])
    assert invoke("codex").exit_code == 7


def test_connection_lost_is_failure(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path, messages=[b"x", ConnectionError("reset")])
    r = invoke("claude")
    assert r.exit_code == 1 and "connection lost" in r.output


def test_server_close_without_exit_is_failure(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path, messages=[b"x"])
    r = invoke("claude")
    assert r.exit_code == 1 and "ended by the server" in r.output


@pytest.mark.parametrize("status,detail", [(403, "no policy allows claude"), (401, "invalid token")])
def test_launch_refusal_shown(monkeypatch, tmp_path, status, detail):
    w = World(monkeypatch, tmp_path, status=status, body={"detail": detail})
    r = invoke("claude")
    assert r.exit_code == 1 and f"launch refused ({status}): {detail}" in r.output and w.ws_urls == []



def test_launcher_never_runs_openshell(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    ran = []
    monkeypatch.setattr(cli.subprocess, "run", lambda args, **k: (ran.append(args), type("R", (), {"stdout": "git@github.com:acme/payments.git\n", "returncode": 0})())[1])
    assert invoke("claude").exit_code == 0
    assert all(a[0] == "git" for a in ran)


def test_unreachable_orchestrator_is_a_clean_error(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    w.unreachable = True
    r = invoke("claude")
    assert r.exit_code == 1 and "cannot reach http://localhost:8083/v1/launch" in r.output


def test_outside_git_repository(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path)
    def fail(*a, **k):
        raise cli.subprocess.CalledProcessError(128, a[0])
    monkeypatch.setattr(cli.subprocess, "check_output", fail)
    r = invoke("claude")
    assert r.exit_code == 1 and "inside a Git repository" in r.output


def id_token(exp):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


def test_token_file_is_private(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HOME", tmp_path)
    monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "token.json")
    (tmp_path / "token.json").write_text("{}")
    os.chmod(tmp_path / "token.json", 0o644)
    cli.save_token({"id_token": id_token(int(time.time()) + 3600)})
    assert stat.S_IMODE(os.stat(tmp_path / "token.json").st_mode) == 0o600


def test_expired_token_without_refresh_asks_login(monkeypatch, tmp_path):
    monkeypatch.delenv("TETHER_TOKEN", raising=False)
    monkeypatch.setattr(cli, "HOME", tmp_path)
    monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "token.json")
    monkeypatch.setattr(cli, "MANAGED_CONFIG", tmp_path / "none.json")
    cli.save_token({"id_token": id_token(int(time.time()) - 10)})
    with pytest.raises(cli.click.ClickException, match="login"):
        cli.load_token()


class TestManagedConfig:
    @pytest.fixture
    def managed(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"orchestrator": "https://agents.company.internal"}))
        os.chmod(cfg, 0o644)
        monkeypatch.setattr(cli, "MANAGED_CONFIG", cfg)
        monkeypatch.setattr(cli, "MANAGED_OWNER_UID", os.getuid())  # tests cannot create root-owned files
        return cfg

    def test_overrides_environment(self, managed, monkeypatch):
        monkeypatch.setenv("TETHER_ORCHESTRATOR", "http://evil.example")
        assert cli.setting("orchestrator") == "https://agents.company.internal"

    def test_dev_token_env_ignored(self, managed, monkeypatch, tmp_path):
        monkeypatch.setenv("TETHER_TOKEN", "dev:kim")
        monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "missing.json")
        with pytest.raises(cli.click.ClickException, match="not logged in"):
            cli.load_token()

    @pytest.mark.parametrize("mode", [0o664, 0o646])
    def test_writable_config_refused(self, managed, mode):
        os.chmod(managed, mode)
        with pytest.raises(cli.click.ClickException, match="root"):
            cli.setting("orchestrator")

    def test_wrong_owner_refused(self, managed, monkeypatch):
        monkeypatch.setattr(cli, "MANAGED_OWNER_UID", os.getuid() + 1)
        with pytest.raises(cli.click.ClickException, match="root"):
            cli.setting("orchestrator")

    def test_secure_websocket_with_client_cert(self, managed, monkeypatch, tmp_path):
        w = World(monkeypatch, tmp_path)
        monkeypatch.setattr(cli, "MANAGED_CONFIG", managed)
        tok = tmp_path / "token.json"
        monkeypatch.setattr(cli, "TOKEN_FILE", tok)
        tok.write_text(json.dumps({"id_token": id_token(int(time.time()) + 3600), "expires_at": int(time.time()) + 3600}))
        assert invoke("claude").exit_code == 0
        assert str(w.requests[0].url) == "https://agents.company.internal/v1/launch"
        assert w.ws_urls[0].startswith("wss://agents.company.internal/v1/attach?ticket=T1")


class CertWorld:
    """No SSO: the client certificate is exchanged for a short-lived token at the orchestrator's front."""
    def __init__(self, monkeypatch, tmp_path, status=200):
        self.calls, self.status, self.expires = [], status, int(time.time()) + 3600
        monkeypatch.delenv("TETHER_TOKEN", raising=False)
        monkeypatch.delenv("TETHER_OIDC_ISSUER", raising=False)
        monkeypatch.setenv("TETHER_CLIENT_CERT", "/certs/kim.pem")
        monkeypatch.setenv("TETHER_CLIENT_KEY", "/certs/kim.key")
        monkeypatch.setenv("TETHER_ORCHESTRATOR", "https://192.168.1.27")
        monkeypatch.setattr(cli, "HOME", tmp_path)
        monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "token.json")
        monkeypatch.setattr(cli, "MANAGED_CONFIG", tmp_path / "none.json")
        monkeypatch.setattr(cli, "http", lambda timeout=10: httpx.Client(transport=httpx.MockTransport(self.handle)))

    def handle(self, req):
        self.calls.append(str(req.url))
        if self.status != 200:
            return httpx.Response(self.status, text="certificate required")
        return httpx.Response(200, json={"token": f"tok{len(self.calls)}", "expires_at": self.expires, "user_id": "kim"})


def test_certificate_login(monkeypatch, tmp_path):
    w = CertWorld(monkeypatch, tmp_path)
    r = invoke("login")
    assert r.exit_code == 0 and "kim" in r.output
    assert w.calls == ["https://192.168.1.27/v1/auth/token"]
    assert cli.load_token() == "tok1" and len(w.calls) == 1   # reused while valid
    assert stat.S_IMODE(os.stat(tmp_path / "token.json").st_mode) == 0o600


def test_certificate_token_renews_silently(monkeypatch, tmp_path):
    w = CertWorld(monkeypatch, tmp_path)
    w.expires = int(time.time()) + 30          # inside the 60 s margin
    assert cli.load_token() == "tok1"
    assert cli.load_token() == "tok2"          # fetched again, no login prompt


def test_certificate_refused_is_a_clean_error(monkeypatch, tmp_path):
    CertWorld(monkeypatch, tmp_path, status=401)
    r = invoke("login")
    assert r.exit_code != 0 and "refused (401)" in r.output
