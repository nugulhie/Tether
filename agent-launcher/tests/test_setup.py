"""tether setup: install the administrator's certificate folder and sign in."""
import base64
import json
import time
import os
import stat

import httpx
import pytest
from click.testing import CliRunner

import tether_launcher.cli as cli
from test_tls import pki, server  # noqa: F401  (real certificates and a real mTLS server)


@pytest.fixture
def env(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setattr(cli, "HOME", home)
    monkeypatch.setattr(cli, "TOKEN_FILE", home / "token.json")
    monkeypatch.setattr(cli, "MANAGED_CONFIG", tmp_path / "none.json")
    for v in cli.ENV_KEYS.values():
        monkeypatch.delenv(v, raising=False)
    monkeypatch.delenv("TETHER_TOKEN", raising=False)
    return home


def folder(pki, tmp_path, config=None, **skip):
    d = tmp_path / "kim-folder"
    d.mkdir()
    for src, dst in (("kim.crt", "cert.pem"), ("kim.key", "key.pem"), ("server-ca.crt", "service-ca.crt")):
        if dst not in skip.get("without", ()):
            (d / dst).write_bytes((pki / src).read_bytes())
    if config is not None:
        (d / "tether.json").write_text(json.dumps(config))
    return d


def invoke(*args):
    return CliRunner().invoke(cli.cli, list(args))


def test_setup_installs_the_folder_and_signs_in(env, tmp_path, pki, server):
    url, seen = server
    d = folder(pki, tmp_path, {"server": url, "model": "qwen3.5:122b"})
    r = invoke("setup", str(d))
    assert r.exit_code == 0, r.output
    assert "Logged in as kim" in r.output and seen == ["kim"]
    cfg = json.loads((env / "config.json").read_text())
    assert cfg == {"orchestrator": url, "client_cert": str(env / "cert.pem"), "client_key": str(env / "key.pem"),
                   "ca_bundle": str(env / "service-ca.crt"), "model": "qwen3.5:122b"}
    for f in ("cert.pem", "key.pem", "service-ca.crt", "config.json"):
        assert stat.S_IMODE(os.stat(env / f).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(env).st_mode) == 0o700
    # From now on every command uses these settings, with no environment variables.
    assert cli.setting("orchestrator") == url and cli.setting("model") == "qwen3.5:122b" and cli.mtls_mode()


def test_environment_still_overrides_the_file(env, tmp_path, pki, server, monkeypatch):
    url, _ = server
    invoke("setup", str(folder(pki, tmp_path, {"server": url})))
    monkeypatch.setenv("TETHER_MODEL", "other")
    assert cli.setting("model") == "other"


def test_server_flag_when_the_folder_has_no_tether_json(env, tmp_path, pki, server):
    url, _ = server
    d = folder(pki, tmp_path)
    assert "--server" in invoke("setup", str(d)).output
    r = invoke("setup", str(d), "--server", url + "/")
    assert r.exit_code == 0, r.output and json.loads((env / "config.json").read_text())["orchestrator"] == url


def test_missing_or_mismatched_files_are_refused_before_anything_is_written(env, tmp_path, pki):
    r = invoke("setup", str(folder(pki, tmp_path, {"server": "https://x"}, without=("key.pem",))))
    assert r.exit_code != 0 and "missing key.pem" in r.output
    d = tmp_path / "mismatch"
    d.mkdir()
    (d / "cert.pem").write_bytes((pki / "kim.crt").read_bytes())
    (d / "key.pem").write_bytes((pki / "server.key").read_bytes())  # someone else's key
    (d / "service-ca.crt").write_bytes((pki / "server-ca.crt").read_bytes())
    r = invoke("setup", str(d), "--server", "https://x")
    assert r.exit_code != 0 and "do not work together" in r.output
    assert not (env / "config.json").exists()


def test_old_token_is_dropped(env, tmp_path, pki, server):
    url, _ = server
    env.mkdir(mode=0o700)
    (env / "token.json").write_text(json.dumps({"id_token": "someone-else", "expires_at": 9999999999}))
    invoke("setup", str(folder(pki, tmp_path, {"server": url})))
    assert json.loads((env / "token.json").read_text())["id_token"] == "t"  # the new identity's token


def test_managed_macs_refuse_setup(env, tmp_path, pki, monkeypatch):
    managed = tmp_path / "managed.json"
    managed.write_text("{}")
    os.chmod(managed, 0o644)
    monkeypatch.setattr(cli, "MANAGED_CONFIG", managed)
    monkeypatch.setattr(cli, "MANAGED_OWNER_UID", os.getuid())
    r = invoke("setup", str(folder(pki, tmp_path, {"server": "https://x"})))
    assert r.exit_code != 0 and "managed" in r.output


# --- company sign-in (OIDC): the same folder for everyone, device certificate optional ---------------------------

class FakeIdP:
    """Discovery, device authorization and token endpoints (RFC 8628), approving on the second poll."""
    issuer = "https://idp.example.com"

    def __init__(self, token=None):
        self.requests, self.polls = [], 0
        self.token = token or {"id_token": "h." + base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + 3600}).encode()).decode().rstrip("=") + ".s",
                               "refresh_token": "r1"}

    def __call__(self, request):
        form = dict(httpx.QueryParams(request.content.decode())) if request.method == "POST" else {}
        self.requests.append((request.url.path, form))
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": self.issuer, "device_authorization_endpoint": self.issuer + "/device",
                                             "token_endpoint": self.issuer + "/token"})
        if request.url.path == "/device":
            return httpx.Response(200, json={"device_code": "dc", "user_code": "ABCD-EFGH", "verification_uri": self.issuer + "/activate",
                                             "interval": 0, "expires_in": 60})
        if request.url.path == "/token":
            self.polls += 1
            if form.get("grant_type", "").endswith("device_code") and self.polls < 2:
                return httpx.Response(400, json={"error": "authorization_pending"})
            return httpx.Response(200, json=self.token)
        return httpx.Response(404)


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(cli, "idp_http", lambda timeout=10: httpx.Client(transport=httpx.MockTransport(fake)))
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    return fake


OIDC = {"oidc_issuer": FakeIdP.issuer, "oidc_client_id": "cid.apps.example", "oidc_client_secret": "public-device-secret",
        "oidc_scope": "openid email profile"}


def test_oidc_folder_without_certificate_signs_in_with_the_device_flow(env, tmp_path, pki, idp):
    d = folder(pki, tmp_path, {"server": "https://10.0.0.5", **OIDC}, without=("cert.pem", "key.pem"))
    r = invoke("setup", str(d))
    assert r.exit_code == 0, r.output
    assert "enter code ABCD-EFGH" in r.output and "Logged in." in r.output
    cfg = json.loads((env / "config.json").read_text())
    assert cfg == {"orchestrator": "https://10.0.0.5", "ca_bundle": str(env / "service-ca.crt"), **OIDC}
    assert not (env / "cert.pem").exists() and not cli.mtls_mode()
    device = next(f for p, f in idp.requests if p == "/device")
    assert device == {"client_id": "cid.apps.example", "scope": "openid email profile"}   # Google rejects offline_access
    polls = [f for p, f in idp.requests if p == "/token"]
    assert all(f["client_secret"] == "public-device-secret" and f["client_id"] == "cid.apps.example" for f in polls)
    assert json.loads((env / "token.json").read_text())["refresh_token"] == "r1"


def test_oidc_folder_keeps_an_optional_device_certificate(env, tmp_path, pki, idp):
    d = folder(pki, tmp_path, {"server": "https://10.0.0.5", **OIDC})
    assert invoke("setup", str(d)).exit_code == 0
    cfg = json.loads((env / "config.json").read_text())
    assert cfg["client_cert"] == str(env / "cert.pem") and cfg["oidc_issuer"] == FakeIdP.issuer
    assert not cli.mtls_mode()   # the certificate names the device; the person signs in with the IdP


def test_oidc_folder_with_half_a_certificate_is_refused(env, tmp_path, pki, idp):
    d = folder(pki, tmp_path, {"server": "https://10.0.0.5", **OIDC}, without=("key.pem",))
    r = invoke("setup", str(d))
    assert r.exit_code == 1 and "missing key.pem" in r.output and not (env / "config.json").exists()


def test_oidc_refresh_sends_the_client_fields(env, tmp_path, pki, idp):
    invoke("setup", str(folder(pki, tmp_path, {"server": "https://10.0.0.5", **OIDC}, without=("cert.pem", "key.pem"))))
    t = json.loads((env / "token.json").read_text()); t["expires_at"] = int(time.time()) - 10
    (env / "token.json").write_text(json.dumps(t))
    assert cli.load_token() == idp.token["id_token"]
    refresh = [f for p, f in idp.requests if p == "/token"][-1]
    assert refresh == {"grant_type": "refresh_token", "refresh_token": "r1", "client_id": "cid.apps.example",
                       "client_secret": "public-device-secret"}


def test_oidc_without_id_token_is_a_clean_error(env, tmp_path, pki, idp):
    idp.token = {"access_token": "a"}
    r = invoke("setup", str(folder(pki, tmp_path, {"server": "https://10.0.0.5", **OIDC}, without=("cert.pem", "key.pem"))))
    assert r.exit_code == 1 and "no ID token" in r.output
