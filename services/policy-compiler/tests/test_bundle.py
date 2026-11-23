import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from policy_compiler import PolicyError
from policy_compiler import bundle as B

POLICIES = Path(__file__).parents[3] / "policies"
BASE = yaml.safe_load((POLICIES / "backend-dev.yaml").read_text())
KEY = Ed25519PrivateKey.generate()
PRIV = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
PUB = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def write(tmp_path, *policies):
    for p in policies:
        (tmp_path / f"{p['policy_id']}.yaml").write_text(yaml.safe_dump(p))
    return tmp_path


def policy(**changes):
    p = copy.deepcopy(BASE)
    p.update(changes)
    return p


def test_repo_policies_are_valid():
    assert [p["policy_id"] for p in B.load_dir(POLICIES)] == ["backend-agent-dev"]


def test_sign_and_verify_roundtrip():
    env = B.sign(B.build(POLICIES, 7, "abc123"), PRIV, "ci-2026")
    assert B.verify(env, PUB)["serial"] == 7


@pytest.mark.parametrize("tamper", [
    lambda e: e["bundle"].update(serial=8),
    lambda e: e["bundle"]["policies"][0]["network"]["allow"].append("evil.com"),
    lambda e: e.update(signature="AAAA"),
    lambda e: e.update(signature="not base64!"),
])
def test_tampered_bundle_rejected(tamper):
    env = B.sign(B.build(POLICIES, 7, "abc123"), PRIV, "ci")
    tamper(env)
    with pytest.raises(PolicyError, match="signature"):
        B.verify(env, PUB)


def test_other_key_rejected():
    other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(PolicyError):
        B.verify(B.sign(B.build(POLICIES, 1, "c"), PRIV, "ci"), other)


@pytest.mark.parametrize("bad,msg", [
    ({"policy_id": "Bad_Id"}, "policy_id"),
    ({"version": 0}, "version"),
    ({"priority": "high"}, "priority"),
    ({"match": {}}, "match.repos"),
    ({"match": {"repos": ["*"], "branch": "main"}}, "unknown match"),
    ({"match": {"repos": ["*"], "environments": ["prod"]}}, "environments"),
    ({"network_binaries": ["/usr/bin/sudo"]}, "sudo"),
])
def test_invalid_policy_files(tmp_path, bad, msg):
    with pytest.raises(PolicyError, match=msg):
        B.load_dir(write(tmp_path, policy(**bad)))


def test_duplicate_priority_rejected(tmp_path):
    with pytest.raises(PolicyError, match="priority"):
        B.load_dir(write(tmp_path, policy(), policy(policy_id="other")))


@pytest.mark.parametrize("repo,normalized", [
    ("git@github.com:co/repo.git", "github.com/co/repo"),
    ("https://github.com/co/repo", "github.com/co/repo"),
    ("https://user@GitHub.com/co/repo.git/", "github.com/co/repo"),
    ("ssh://git@github.com:22/co/repo.git", "github.com/co/repo"),
    ("/Users/kim/src/repo", "local:/Users/kim/src/repo"),
])
def test_normalize_repo(repo, normalized):
    assert B.normalize_repo(repo) == normalized


@pytest.mark.parametrize("match,repo,env,groups,expected", [
    ({"repos": ["*"]}, "git@github.com:co/r.git", "development", [], True),
    ({"repos": ["github.com/co/*"]}, "git@github.com:co/r.git", "development", [], True),
    ({"repos": ["github.com/co/*"]}, "git@github.com:other/r.git", "development", [], False),
    ({"repos": ["github.com/co/*"]}, "git@github.com.evil.io:co/r.git", "development", [], False),
    ({"repos": ["*"], "environments": ["development"]}, "x", "production", [], False),
    ({"repos": ["*"], "groups": ["backend"]}, "x", "development", ["frontend"], False),
    ({"repos": ["*"], "groups": ["backend"]}, "x", "development", ["backend", "x"], True),
    ({}, "x", "development", [], False),
])
def test_matches(match, repo, env, groups, expected):
    assert B.matches({"match": match}, repo, env, groups) is expected


def test_cli_validate_and_bundle(tmp_path):
    run = lambda *a: subprocess.run([sys.executable, "-m", "policy_compiler.bundle", *a], capture_output=True, text=True)
    assert run("keygen", str(tmp_path / "k.pem"), str(tmp_path / "k.pub")).returncode == 0
    assert oct((tmp_path / "k.pem").stat().st_mode)[-3:] == "600"
    assert f"ok backend-agent-dev v{BASE['version']}" in run("validate", str(POLICIES)).stdout
    r = run("bundle", str(POLICIES), "--serial", "3", "--commit", "abc", "--key", str(tmp_path / "k.pem"), "--key-id", "ci", "--out", str(tmp_path / "b.json"))
    assert r.returncode == 0, r.stderr
    env = json.loads((tmp_path / "b.json").read_text())
    assert B.verify(env, (tmp_path / "k.pub").read_bytes())["serial"] == 3
    bad = write(tmp_path / "bad" if (tmp_path / "bad").mkdir() is None else None, policy(version=0))
    r = run("validate", str(bad))
    assert r.returncode == 1 and "version" in r.stderr
