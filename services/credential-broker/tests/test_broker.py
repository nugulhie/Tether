import json
from datetime import datetime, timedelta, timezone

import boto3
import httpx
import jwt
import pytest
from botocore.stub import ANY, Stubber
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import broker.main as b

ROLE = "arn:aws:iam::123456789012:role/AIAgentDevelopmentRole"
APP_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
USER = {"Authorization": "Bearer user-token"}


def session(**overrides):
    s = {"session_id": "11111111-2222-3333-4444-555555555555", "user_id": "kim@company.com", "device_id": "mac-1",
         "agent": "claude", "repo": "git@github.com:co/repo.git", "environment": "development",
         "expires_at": (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
         "policy": {"aws": {"role": ROLE, "duration_seconds": 3600},
                    "github": {"permissions": {"contents": "write", "metadata": "read"}}}}
    s.update(overrides)
    return s


class Fake:
    """Policy API + GitHub API stand-in recording every request."""

    def __init__(self, sess, session_status=200):
        self.sess, self.session_status, self.requests, self.audits = sess, session_status, [], []
        self.github_revoked = []

    def __call__(self, req: httpx.Request):
        self.requests.append(req)
        path = req.url.path
        if path.startswith("/v1/agent/sessions/"):
            assert req.headers["authorization"] == "Bearer user-token"
            if self.session_status != 200:
                return httpx.Response(self.session_status, json={"detail": "nope"})
            return httpx.Response(200, json=self.sess)
        if path == "/v1/audit/events":
            assert req.headers["authorization"] == "Bearer broker-secret"
            self.audits.append(json.loads(req.content))
            return httpx.Response(200, json={"accepted": True})
        if path == "/repos/co/repo/installation":
            claims = jwt.decode(req.headers["authorization"].split()[1], APP_KEY.public_key(), algorithms=["RS256"])
            assert claims["iss"] == "4242" and claims["exp"] - claims["iat"] <= 600
            return httpx.Response(200, json={"id": 99})
        if path == "/repos/co/missing/installation":
            return httpx.Response(404, json={})
        if path == "/app/installations/99/access_tokens":
            return httpx.Response(201, json={"token": "ghs_x", "expires_at": "2099-10-01T01:00:00Z", **json.loads(req.content)})
        if path == "/installation/token" and req.method == "DELETE":
            self.github_revoked.append(req.headers["authorization"])
            return httpx.Response(204)
        return httpx.Response(500)


@pytest.fixture(autouse=True)
def fresh_store(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("BROKER_ENCRYPTION_KEY", Fernet.generate_key().decode())
    b.store.reset()
    yield
    b.store.reset()


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("POLICY_API", "http://policy-api")
    monkeypatch.setenv("CREDENTIAL_BROKER_TOKEN", "broker-secret")
    monkeypatch.setenv("GITHUB_APP_ID", "4242")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", APP_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


def fake(monkeypatch, sess=None, status=200):
    f = Fake(sess or session(), status)
    monkeypatch.setattr(b, "http_transport", httpx.MockTransport(f))
    return f


def sts(monkeypatch):
    client = boto3.client("sts", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(client)
    monkeypatch.setattr(b, "sts_client", lambda: client)
    return stub


client = TestClient(b.app)
STS_RESPONSE = {"Credentials": {"AccessKeyId": "ASIAEXAMPLEEXAMPLE", "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": datetime(2099, 10, 1, tzinfo=timezone.utc)},
                "AssumedRoleUser": {"Arn": f"{ROLE}/agent-x", "AssumedRoleId": "AROAEXAMPLEEXAMPLE:agent-x"}}


def test_aws_assumes_role_with_session_tags(env, monkeypatch):
    f = fake(monkeypatch)
    stub = sts(monkeypatch)
    stub.add_response("assume_role", STS_RESPONSE, {
        "RoleArn": ROLE, "RoleSessionName": "agent-11111111-2222-3333-4444-555555555555", "DurationSeconds": 3600,
        "SourceIdentity": "kim@company.com",
        "Tags": [{"Key": "user", "Value": "kim@company.com"}, {"Key": "device", "Value": "mac-1"},
                 {"Key": "repo", "Value": "git@github.com:co/repo.git"}, {"Key": "agent", "Value": "claude"},
                 {"Key": "session_id", "Value": "11111111-2222-3333-4444-555555555555"}]})
    with stub:
        r = client.post("/v1/credentials/aws", json={"session_id": "s1"}, headers=USER)
    assert r.status_code == 200, r.text
    assert r.json() == {"Version": 1, "AccessKeyId": "ASIAEXAMPLEEXAMPLE", "SecretAccessKey": "s", "SessionToken": "t", "Expiration": "2099-10-01T00:00:00+00:00"}
    assert f.audits[-1]["event_type"] == "credential.issue" and f.audits[-1]["success"] is True
    assert f.audits[-1]["user_id"] == "kim@company.com"


def test_aws_duration_capped_by_session_expiry(env, monkeypatch):
    fake(monkeypatch, session(expires_at=(datetime.now(timezone.utc) + timedelta(seconds=1200)).isoformat()))
    stub = sts(monkeypatch)
    stub.add_response("assume_role", STS_RESPONSE, {"RoleArn": ROLE, "RoleSessionName": ANY, "DurationSeconds": ANY, "SourceIdentity": ANY, "Tags": ANY})
    captured = {}
    stub.client.meta.events.register("provide-client-params.sts.AssumeRole", lambda params, **_: captured.update(params))
    with stub:
        assert client.post("/v1/credentials/aws", json={"session_id": "s1"}, headers=USER).status_code == 200
    assert 900 <= captured["DurationSeconds"] <= 1200


def test_aws_refused_when_session_nearly_expired(env, monkeypatch):
    fake(monkeypatch, session(expires_at=(datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat()))
    sts(monkeypatch)
    assert client.post("/v1/credentials/aws", json={"session_id": "s1"}, headers=USER).status_code == 410


def test_aws_denied_without_role(env, monkeypatch):
    f = fake(monkeypatch, session(policy={"aws": {"role": None}}))
    sts(monkeypatch)
    assert client.post("/v1/credentials/aws", json={"session_id": "s1"}, headers=USER).status_code == 403
    assert f.audits[-1]["success"] is False


@pytest.mark.parametrize("kind", ["aws", "github"])
def test_production_never_gets_credentials(env, monkeypatch, kind):
    fake(monkeypatch, session(environment="production"))
    assert client.post(f"/v1/credentials/{kind}", json={"session_id": "s1"}, headers=USER).status_code == 403


@pytest.mark.parametrize("status", [401, 404, 409, 410])
def test_policy_api_rejection_passed_through(env, monkeypatch, status):
    fake(monkeypatch, status=status)
    assert client.post("/v1/credentials/aws", json={"session_id": "s1"}, headers=USER).status_code == status


def test_requires_bearer(env, monkeypatch):
    f = fake(monkeypatch)
    assert client.post("/v1/credentials/aws", json={"session_id": "s1"}).status_code == 401
    assert f.requests == []


def test_github_token_scoped_to_repo_and_policy(env, monkeypatch):
    f = fake(monkeypatch)
    r = client.post("/v1/credentials/github", json={"session_id": "s1"}, headers=USER)
    assert r.status_code == 200, r.text
    assert r.json()["repository"] == "co/repo"
    req = json.loads(next(x for x in f.requests if x.url.path.endswith("/access_tokens")).content)
    assert req == {"repositories": ["repo"], "permissions": {"contents": "write", "metadata": "read"}}
    assert f.audits[-1]["data"]["repository"] == "co/repo"
    assert "ghs_x" not in json.dumps(f.audits)


def test_github_app_not_installed(env, monkeypatch):
    fake(monkeypatch, session(repo="https://github.com/co/missing.git"))
    assert client.post("/v1/credentials/github", json={"session_id": "s1"}, headers=USER).status_code == 403


@pytest.mark.parametrize("repo,expected", [
    ("git@github.com:co/repo.git", ("co", "repo")),
    ("https://github.com/co/repo", ("co", "repo")),
    ("https://github.com/co/my.repo.git", ("co", "my.repo")),
    ("ssh://git@github.com/co/repo.git", ("co", "repo")),
])
def test_github_repo_parsing(repo, expected):
    assert b.github_repo(repo) == expected


@pytest.mark.parametrize("repo", ["/Users/kim/src/repo", "git@gitlab.com:co/repo.git", "https://github.com.evil.io/co/repo", "https://github.com/co/repo/../x"])
def test_github_rejects_non_github_repo(repo):
    with pytest.raises(b.HTTPException):
        b.github_repo(repo)


def test_tag_and_source_identity_sanitized():
    assert b.tag_value("a<b>!" * 100) == ("a_b__" * 100)[:256]
    assert b.tag_value("a\tb\nc d") == "a_b_c d"
    assert b.source_identity("k") == "k_"
    assert b.source_identity("김 dev") == "__dev"


def test_github_refused_without_encryption_key(env, monkeypatch):
    fake(monkeypatch)
    monkeypatch.delenv("BROKER_ENCRYPTION_KEY")
    assert client.post("/v1/credentials/github", json={"session_id": "s1"}, headers=USER).status_code == 503


def test_github_token_stored_encrypted(env, monkeypatch):
    fake(monkeypatch)
    client.post("/v1/credentials/github", json={"session_id": "s1"}, headers=USER)
    raw = b.store.db().execute("SELECT secret FROM issued WHERE kind='github'").fetchone()[0]
    assert b"ghs_x" not in raw


# --- kill switch ----------------------------------------------------------------

ORCH = {"Authorization": "Bearer orch-secret"}


def issue_both(monkeypatch):
    f = fake(monkeypatch)
    stub = sts(monkeypatch)
    stub.add_response("assume_role", STS_RESPONSE, {"RoleArn": ANY, "RoleSessionName": ANY, "DurationSeconds": ANY, "SourceIdentity": ANY, "Tags": ANY})
    with stub:
        assert client.post("/v1/credentials/aws", json={"session_id": "s1"}, headers=USER).status_code == 200
    assert client.post("/v1/credentials/github", json={"session_id": "s1"}, headers=USER).status_code == 200
    return f


def iam(monkeypatch):
    c = boto3.client("iam", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(c)
    monkeypatch.setattr(b, "iam_client", lambda: c)
    return stub


def test_revoke_requires_orchestrator(env, monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_TOKEN", "orch-secret")
    for h in (USER, {"Authorization": "Bearer broker-secret"}, {}):
        assert client.post("/v1/admin/revoke", headers=h, json={"session_ids": ["x"], "reason": "r"}).status_code == 403


def test_revoke_denies_aws_session_and_revokes_github_token(env, monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_TOKEN", "orch-secret")
    f = issue_both(monkeypatch)
    sid = session()["session_id"]
    stub = iam(monkeypatch)
    captured = {}
    stub.client.meta.events.register("provide-client-params.iam.PutRolePolicy", lambda params, **_: captured.update(params))
    stub.add_response("put_role_policy", {}, {"RoleName": "AIAgentDevelopmentRole", "PolicyName": "TetherRevokedSessions", "PolicyDocument": ANY})
    with stub:
        r = client.post("/v1/admin/revoke", headers=ORCH, json={"session_ids": [sid], "reason": "INC-7"})
    assert r.status_code == 200, r.text
    assert r.json()["aws_sessions_denied"] == 1 and r.json()["github_tokens_revoked"] == 1
    doc = json.loads(captured["PolicyDocument"])
    st = doc["Statement"][0]
    assert (st["Effect"], st["Action"], st["Resource"]) == ("Deny", "*", "*")
    assert st["Condition"]["StringEquals"]["aws:PrincipalTag/session_id"] == [sid]
    assert f.github_revoked == ["Bearer ghs_x"]


def test_revoked_list_accumulates_and_prunes_expired(env, monkeypatch):
    import time as _t
    b.store.mark_revoked("old", "arn:aws:iam::123456789012:role/R", _t.time() - 1)
    b.store.mark_revoked("live-1", "arn:aws:iam::123456789012:role/R", _t.time() + 3600)
    b.store.mark_revoked("live-2", "arn:aws:iam::123456789012:role/R", _t.time() + 3600)
    assert b.store.revoked_live("arn:aws:iam::123456789012:role/R") == ["live-1", "live-2"]


def test_revoke_reports_failures_loudly(env, monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_TOKEN", "orch-secret")
    issue_both(monkeypatch)
    stub = iam(monkeypatch)
    stub.add_client_error("put_role_policy", "AccessDenied", "not allowed")
    with stub:
        r = client.post("/v1/admin/revoke", headers=ORCH, json={"session_ids": [session()["session_id"]], "reason": "INC-7"})
    assert r.status_code == 502 and "aws deny policy" in json.dumps(r.json())
