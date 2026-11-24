"""tether setup: install the administrator's certificate folder and sign in."""
import json
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
