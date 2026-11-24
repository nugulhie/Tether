import re
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from conftest import ORCHESTRATOR, start_session
from sqlalchemy.pool import StaticPool

import app.auth as auth
import app.main as m
from app.db import migrate
from sqlalchemy import create_engine

# Each test runs against a fresh migrated database (see conftest.fresh_db).
client = TestClient(m.app)

USER = {"Authorization": "Bearer dev:Kim.Dev"}
SESSION = {"device_id": "mac-1", "agent": "claude", "repo": "git@github.com:co/repo.git"}


def new_session(headers=USER, **body):
    r = start_session(client, {**SESSION, **body}, headers)
    assert r.status_code == 200, r.text
    return r.json()


def session_headers(**body):
    return {"Authorization": f"Bearer {new_session(**body)['session_token']}"}


def check(action, resource, headers=None):
    r = client.post("/v1/permissions/check", json={"action": action, "resource": resource}, headers=headers or session_headers())
    assert r.status_code == 200, r.text
    return r.json()


def audit_rows(event_type):
    with m.Session() as db:
        return [e.payload for e in db.query(m.AuditEvent).filter_by(event_type=event_type).order_by(m.AuditEvent.id)]


# --- authentication ---------------------------------------------------------

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic x"}, {"Authorization": "Bearer nope"}, {"Authorization": "Bearer dev:"}])
def test_session_requires_user_token(headers):
    assert start_session(client, SESSION, headers).status_code in (401, 422)


def test_users_cannot_create_sessions_directly():
    # Session tokens only ever go to the orchestrator, never to a developer machine.
    assert client.post("/v1/agent/sessions", json={**SESSION, "user_token": "dev:Kim.Dev"}, headers=USER).status_code == 403
    assert "session_token" in start_session(client, SESSION, USER).json()


def test_user_id_comes_from_token_not_body():
    s = new_session(user_id="someone-else")
    assert s["user_id"] == "Kim.Dev"
    assert s["sandbox_name"] == new_session()["sandbox_name"]
    assert s["sandbox_name"] != new_session(headers={"Authorization": "Bearer dev:someone-else"})["sandbox_name"]


def test_permission_check_requires_session_token():
    r = client.post("/v1/permissions/check", json={"action": "network_connect", "resource": "github.com"}, headers=USER)
    assert r.status_code == 403


def test_expired_session_token_rejected(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_SECONDS", "-1")
    r = client.post("/v1/permissions/check", json={"action": "x", "resource": "y"}, headers=session_headers())
    assert r.status_code == 401


def test_verified_device_from_orchestrator():
    s = new_session(headers={**USER, "X-Client-Cert-Fingerprint": "sha256:abc"})
    ev = audit_rows("session.create")[-1]
    assert ev["actor"]["session"]["uid"] == s["session_id"]
    assert ev["device"] == {"uid": "sha256:abc", "type_id": 0, "is_trusted": True}


class TestOIDC:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @pytest.fixture(autouse=True)
    def oidc(self, monkeypatch):
        monkeypatch.setenv("AUTH_MODE", "oidc")
        monkeypatch.setenv("OIDC_ISSUER", "https://idp.example.com")
        monkeypatch.setenv("OIDC_AUDIENCE", "tether")
        monkeypatch.setenv("OIDC_JWKS_URL", "https://idp.example.com/jwks")
        pub = self.key.public_key()

        class FakeJWKS:
            def get_signing_key_from_jwt(self, token):
                return type("K", (), {"key": pub})()
        monkeypatch.setattr(auth, "_jwks", lambda url: FakeJWKS())

    def token(self, key=None, **claims):
        now = int(time.time())
        c = {"iss": "https://idp.example.com", "aud": "tether", "iat": now, "exp": now + 300, "email": "lee@company.com", **claims}
        return {"Authorization": "Bearer " + jwt.encode(c, key or self.key, algorithm="RS256")}

    def test_valid_token(self):
        assert new_session(headers=self.token())["user_id"] == "lee@company.com"

    @pytest.mark.parametrize("claims", [
        {"aud": "other"},
        {"iss": "https://evil.example.com"},
        {"exp": int(time.time()) - 3600},
        {"email": None},
    ])
    def test_rejects_bad_claims(self, claims):
        assert start_session(client, SESSION, self.token(**claims)).status_code == 401

    def test_rejects_wrong_signature(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert start_session(client, SESSION, self.token(key=other)).status_code == 401

    def test_dev_tokens_rejected(self):
        assert start_session(client, SESSION, USER).status_code == 401


# --- sessions ---------------------------------------------------------------

def test_session_returns_compiled_policy_and_stable_sandbox_name():
    a, b = new_session(), new_session()
    assert a["session_id"] != b["session_id"]
    assert a["session_token"] != b["session_token"]
    assert a["sandbox_name"] == b["sandbox_name"]
    assert m.SANDBOX_NAME.fullmatch(a["sandbox_name"]) and a["sandbox_name"].startswith("a-")
    assert a["openshell_policy"]["filesystem_policy"]["read_write"][0] == "/workspace"
    assert a["openshell_policy"]["process"]["run_as_user"] == "sandbox"


def test_sandbox_name_differs_per_repo():
    assert new_session()["sandbox_name"] != new_session(repo="other")["sandbox_name"]


@pytest.mark.parametrize("user_id", ["../../etc", "a b;rm -rf", "x" * 128])
def test_sandbox_name_is_sanitized(user_id):
    name = new_session(headers={"Authorization": f"Bearer dev:{user_id}"})["sandbox_name"]
    # OpenShell's rules for a sandbox name: at most 19 characters, a DNS-1123 label, no "--".
    assert len(name) <= 19 and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", name) and "--" not in name


def test_rejects_unusable_user_id():
    assert start_session(client, SESSION, {"Authorization": "Bearer dev:!!!"}).status_code == 422


def test_session_token_not_stored_in_plaintext():
    s = new_session()
    with m.Session() as db:
        assert db.get(m.SessionToken, s["session_id"]).token_hash != s["session_token"]


def test_get_session_only_for_owner():
    s = new_session()
    r = client.get(f"/v1/agent/sessions/{s['session_id']}", headers=USER)
    assert r.status_code == 200
    assert r.json()["policy"]["github"]["permissions"]["contents"] == "write"
    assert client.get(f"/v1/agent/sessions/{s['session_id']}", headers={"Authorization": "Bearer dev:mallory"}).status_code == 404
    assert client.get(f"/v1/agent/sessions/{s['session_id']}", headers={"Authorization": f"Bearer {s['session_token']}"}).status_code == 403


def test_get_session_rejects_superseded_policy(publish):
    s = new_session()
    publish(network={"allow": ["github.com"]}, version=V+1)
    assert client.get(f"/v1/agent/sessions/{s['session_id']}", headers=USER).status_code == 409
    r = check("network_connect", "github.com", headers={"Authorization": f"Bearer {s['session_token']}"})
    assert (r["decision"], r["reason_code"]) == ("DENY", "POLICY_SUPERSEDED")


def test_get_session_rejects_expired():
    s = new_session()
    with m.Session() as db:
        db.get(m.SessionToken, s["session_id"]).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1); db.commit()
    assert client.get(f"/v1/agent/sessions/{s['session_id']}", headers=USER).status_code == 410


# --- permission decisions ---------------------------------------------------

@pytest.mark.parametrize("resource,decision", [
    ("github.com", "ALLOW"),
    ("https://github.com/co/repo", "ALLOW"),
    ("api.github.com:443", "ALLOW"),
    ("GitHub.com.", "ALLOW"),
    ("evil.github.com", "DENY"),
    ("github.com.evil.io", "DENY"),
    ("example.com", "DENY"),
])
def test_network_connect(resource, decision):
    assert check("network_connect", resource)["decision"] == decision


@pytest.mark.parametrize("resource,decision,code", [
    ("git", "ALLOW", "PROCESS_ALLOWED"),
    ("/usr/bin/git", "ALLOW", "PROCESS_ALLOWED"),
    ("sudo", "DENY", "PROCESS_DENIED"),
    ("/usr/bin/docker", "DENY", "PROCESS_DENIED"),
    ("curl", "DENY", "PROCESS_NOT_ALLOWED"),
])
def test_process_exec(resource, decision, code):
    r = check("process_exec", resource)
    assert (r["decision"], r["reason_code"]) == (decision, code)


@pytest.mark.parametrize("action,resource,decision", [
    ("file_write", "/workspace/src/a.py", "ALLOW"),
    ("file_write", "/tmp/x", "ALLOW"),
    ("file_write", "/usr/lib/x", "DENY"),
    ("file_write", "/workspace/../etc/passwd", "DENY"),
    ("file_write", "/workspacex/a", "DENY"),
    ("file_read", "/usr/lib/x", "ALLOW"),
    ("file_read", "/Users/kim/.ssh/id_rsa", "DENY"),
    ("file_read", "relative/path", "DENY"),
    ("file_read", "//Users/kim/.ssh/id_rsa", "DENY"),
    ("file_write", "//workspace/a", "ALLOW"),
])
def test_file_access(action, resource, decision):
    assert check(action, resource)["decision"] == decision


def test_unknown_action_is_denied():
    r = check("delete_repo", "co/repo")
    assert (r["decision"], r["reason_code"]) == ("DENY", "UNKNOWN_ACTION")


def test_s3_denied_without_role_and_for_prod():
    assert check("s3_read", "s3://dev-bucket/a")["reason_code"] == "AWS_NOT_GRANTED"
    assert check("s3_read", "s3://prod-bucket/a")["reason_code"] == "PRODUCTION_DATA"


def test_production_has_no_policy():
    r = start_session(client, {**SESSION, "environment": "production"}, USER)
    assert r.status_code == 403 and "no policy" in r.json()["detail"]


# --- audit ------------------------------------------------------------------

def test_permission_check_is_audited_as_ocsf():
    s = new_session()
    check("process_exec", "sudo", headers={"Authorization": f"Bearer {s['session_token']}"})
    ev = audit_rows("permission.check")[-1]
    assert ev["class_uid"] == 6003 and ev["type_uid"] == 600302
    assert ev["actor"] == {"user": {"uid": "Kim.Dev"}, "session": {"uid": s["session_id"]}}
    assert ev["device"]["is_trusted"] is False
    assert (ev["disposition_id"], ev["disposition"]) == (2, "Blocked")
    assert ev["unmapped"]["reason_code"] == "PROCESS_DENIED"


def test_orchestrator_reports_sandbox_lifecycle():
    s = new_session()
    body = {"event_type": "agent.exit", "session_id": s["session_id"], "success": False, "data": {"returncode": 2}, "user_id": "Kim.Dev", "device_id": "mac-1"}
    assert client.post("/v1/audit/events", headers=USER, json=body).status_code == 422  # users report nothing
    assert client.post("/v1/audit/events", headers=ORCHESTRATOR, json=body).status_code == 200
    ev = audit_rows("agent.exit")[-1]
    assert ev["class_uid"] == 1007 and ev["activity_name"] == "Terminate" and ev["status_id"] == 2
    assert ev["actor"]["user"]["uid"] == "Kim.Dev"
    assert ev["metadata"]["log_provider"] == "sandbox-orchestrator"
    assert client.post("/v1/audit/events", headers=ORCHESTRATOR, json={**body, "event_type": "credential.issue"}).status_code == 422


def test_client_cannot_report_for_others_session_or_server_events():
    s = new_session()
    mallory = {"Authorization": "Bearer dev:mallory"}
    assert client.post("/v1/audit/events", headers=mallory, json={"event_type": "agent.exit", "session_id": s["session_id"]}).status_code == 422
    for t in ("credential.issue", "permission.check", "session.create", "made.up"):
        assert client.post("/v1/audit/events", headers=USER, json={"event_type": t}).status_code == 422


def test_broker_reports_credential_issue():
    s = new_session()
    broker = {"Authorization": "Bearer broker-secret"}
    body = {"event_type": "credential.issue", "session_id": s["session_id"], "user_id": "Kim.Dev", "device_id": "mac-1", "data": {"kind": "aws"}}
    assert client.post("/v1/audit/events", headers=broker, json=body).status_code == 200
    ev = audit_rows("credential.issue")[-1]
    assert ev["actor"]["user"]["uid"] == "Kim.Dev"
    assert ev["metadata"]["log_provider"] == "credential-broker"
    assert client.post("/v1/audit/events", headers=broker, json={**body, "event_type": "agent.exit"}).status_code == 422
    assert client.post("/v1/agent/sessions", headers=broker, json=SESSION).status_code == 403


# --- policy bundles and selection ---------------------------------------------

import base64  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from policy_compiler import bundle as B  # noqa: E402
from conftest import BASE, PUBLISHER  # noqa: E402
V = BASE["version"]


def policy(**kw):
    import copy
    return {**copy.deepcopy(BASE), **kw}


def current_serial():
    return client.get("/v1/policies/bundle/current", headers=USER).json()["serial"]


def test_repository_policies_loaded_at_startup():
    cur = client.get("/v1/policies/bundle/current", headers=USER).json()
    assert cur["active"] == [f"backend-agent-dev@{V}"]


def test_only_publisher_can_publish():
    body = {"format": 1, "serial": 999, "git_commit": "x", "policies": [BASE]}
    for h in (USER, {"Authorization": "Bearer broker-secret"}, session_headers()):
        assert client.post("/v1/policies/bundle", headers=h, json=body).status_code == 403


def test_replayed_serial_rejected(publish):
    s = current_serial()
    r = client.post("/v1/policies/bundle", headers=PUBLISHER, json={"format": 1, "serial": s, "git_commit": "x", "policies": [BASE]})
    assert r.status_code == 409 and "not newer" in r.json()["detail"]


def test_change_requires_version_bump(publish):
    r = publish(network={"allow": ["github.com"]}, expect=409)
    assert "without a version bump" in r["detail"]


def test_new_version_below_latest_rejected(publish):
    publish(version=V+2, network={"allow": ["github.com"]})
    assert "older than" in publish(version=V+1, network={"allow": ["pypi.org"]}, expect=409)["detail"]


def test_rollback_to_identical_published_version(publish):
    publish(version=V+4, network={"allow": ["github.com"]})
    r = publish()  # the repository version, unchanged: a reviewed revert
    assert r["rollbacks"] == [f"backend-agent-dev@{V+4}->{V}"]
    assert audit_rows("policy.publish")[-1]["unmapped"]["rollbacks"] == [f"backend-agent-dev@{V+4}->{V}"]
    assert new_session()["policy_version"] == V


def test_invalid_policy_in_bundle_rejected(publish):
    publish(version=V+1, network_binaries=["/usr/bin/sudo"], expect=422)


def test_removed_policies_deactivated(publish):
    publish(policy(policy_id="team-x", version=1, priority=10, match={"repos": ["github.com/co/*"]}))
    publish()  # bundle without team-x
    s = new_session()
    assert s["policy_id"] == "backend-agent-dev"


def test_selection_by_priority_repo_and_group(publish):
    publish(
        policy(policy_id="payments", version=1, priority=20, match={"repos": ["github.com/co/payments*"], "groups": ["payments"]}, network={"allow": ["github.com"]}),
        policy(policy_id="co-repos", version=1, priority=10, match={"repos": ["github.com/co/*"]}, network={"allow": ["github.com", "pypi.org"]}),
    )
    pay = {"Authorization": "Bearer dev:Kim.Dev:payments,eng"}
    assert new_session(headers=pay, repo="git@github.com:co/payments-api.git")["policy_id"] == "payments"
    assert new_session(repo="git@github.com:co/payments-api.git")["policy_id"] == "co-repos"  # no group
    assert new_session(repo="https://github.com/co/web")["policy_id"] == "co-repos"
    assert new_session(repo="git@github.com:other/x.git")["policy_id"] == "backend-agent-dev"


def test_session_pins_policy_hash():
    s = new_session()
    with m.Session() as db:
        assert db.get(m.AgentSession, s["session_id"]).policy_hash == s["policy_hash"]


def test_network_change_keeps_sandbox_static_change_does_not(publish):
    before = new_session()
    publish(version=V+1, network={"allow": ["github.com"]})
    net = new_session()
    assert net["sandbox_name"] == before["sandbox_name"]
    assert net["policy_hash"] != before["policy_hash"]
    assert [r["endpoints"][0]["host"] for r in net["openshell_policy"]["network_policies"].values()] == ["github.com"]
    publish(version=V+2, network={"allow": ["github.com"]}, filesystem={"read_only": ["/usr"], "read_write": ["/tmp"]})
    assert new_session()["sandbox_name"] != before["sandbox_name"]
    publish(version=V+3, network={"allow": ["github.com"]}, github={"org": "your-org", "permissions": {"contents": "read"}})
    assert new_session()["sandbox_name"] != before["sandbox_name"]  # credential providers changed


def test_signed_bundles(publish, monkeypatch):
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    monkeypatch.setenv("POLICY_BUNDLE_PUBLIC_KEY", key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    bundle = {"format": 1, "serial": current_serial() + 1, "git_commit": "abc", "policies": [policy(version=V+1, network={"allow": ["github.com"]})]}
    # Once a key is configured, unsigned bundles are refused even in dev mode.
    assert client.post("/v1/policies/bundle", headers=PUBLISHER, json=bundle).status_code == 422
    env = B.sign(bundle, priv, "ci-2026")
    forged = {**env, "bundle": {**bundle, "policies": [policy(version=V+1, network={"allow": ["evil.com"]})]}}
    assert client.post("/v1/policies/bundle", headers=PUBLISHER, json=forged).status_code == 422
    r = client.post("/v1/policies/bundle", headers=PUBLISHER, json=env)
    assert r.status_code == 200, r.text
    cur = client.get("/v1/policies/bundle/current", headers=USER).json()
    assert (cur["signed"], cur["key_id"], cur["git_commit"]) == (True, "ci-2026", "abc")
    ev = audit_rows("policy.publish")[-1]
    assert ev["actor"]["user"]["uid"] == "policy-publisher" and ev["unmapped"]["active"] == [f"backend-agent-dev@{V+1}"]


def test_unsigned_rejected_outside_dev(publish, monkeypatch):
    serial = current_serial() + 1
    monkeypatch.setenv("AUTH_MODE", "oidc")
    r = client.post("/v1/policies/bundle", headers=PUBLISHER, json={"format": 1, "serial": serial, "git_commit": "x", "policies": [BASE]})
    assert r.status_code == 422 and "signed" in r.json()["detail"]


def test_effective_policy_for_user_and_session():
    assert client.get("/v1/policies/effective", params={"repo": "git@github.com:co/r.git"}, headers=USER).json()["id"] == "backend-agent-dev"
    assert client.get("/v1/policies/effective", params={"repo": "x", "environment": "production"}, headers=USER).status_code == 404
    assert client.get("/v1/policies/effective", headers=session_headers()).json()["version"] == V


# --- migrations ---------------------------------------------------------------

def test_migrates_pre_alembic_database():
    """A database created by the P0 code (create_all, no session_tokens) upgrades in place."""
    from sqlalchemy import inspect, text
    e = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with e.begin() as c:
        c.execute(text("CREATE TABLE policies (id VARCHAR(128) PRIMARY KEY, version INTEGER NOT NULL, document JSON NOT NULL, enabled BOOLEAN)"))
        c.execute(text("""INSERT INTO policies VALUES ('backend-agent-dev', 2, '{"a": 1}', 1)"""))
        c.execute(text("CREATE TABLE agent_sessions (id VARCHAR(128) PRIMARY KEY, user_id VARCHAR(128), device_id VARCHAR(128), agent VARCHAR(64), repo VARCHAR(1024), environment VARCHAR(64), policy_id VARCHAR(128), policy_version INTEGER, sandbox_name VARCHAR(128), created_at DATETIME)"))
        c.execute(text("INSERT INTO agent_sessions (id, user_id) VALUES ('old', 'kim')"))
        c.execute(text("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, event_type VARCHAR(128), payload JSON, created_at DATETIME)"))
    migrate(bind=e)
    insp = inspect(e)
    assert {"session_tokens", "policy_bundles", "alembic_version"} <= set(insp.get_table_names())
    assert insp.get_pk_constraint("policies")["constrained_columns"] == ["id", "version"]
    assert "policy_hash" in {c["name"] for c in insp.get_columns("agent_sessions")}
    with e.connect() as c:
        assert c.execute(text("SELECT active FROM policies")).scalar() == 0  # unsigned seed is not selectable
        assert c.execute(text("SELECT user_id FROM agent_sessions WHERE id='old'")).scalar() == "kim"
    migrate(bind=e)  # idempotent
    # The legacy seed (v2, never published) must not block publishing the repository policy,
    # even when the repository policy has the same version number.
    import app.main as m
    m.Session.configure(bind=e)
    m.load_dev_policies()
    assert new_session()["policy_version"] == V
    with m.Session() as db:
        assert db.get(m.Policy, ("backend-agent-dev", V)).document != {"a": 1}


# --- LLM gateway introspection -------------------------------------------------

GATEWAY = {"Authorization": "Bearer gateway-secret"}


def introspect(token, headers=GATEWAY):
    return client.post("/v1/sessions/introspect", headers=headers, json={"session_token": token})


def test_introspect_returns_identity_and_model_grants():
    s = new_session()
    r = introspect(s["session_token"])
    assert r.status_code == 200
    body = r.json()
    assert (body["session_id"], body["user_id"], body["policy_version"]) == (s["session_id"], "Kim.Dev", V)
    assert body["llm"]["anthropic"]["models"] == BASE["llm"]["anthropic"]["models"]


def test_introspect_only_for_gateway():
    s = new_session()
    for h in (USER, ORCHESTRATOR, {"Authorization": "Bearer broker-secret"}, {"Authorization": f"Bearer {s['session_token']}"}):
        assert introspect(s["session_token"], headers=h).status_code == 403


@pytest.mark.parametrize("token", ["ast_unknown", "dev:Kim.Dev", "sk-ant-oat01-x"])
def test_introspect_rejects_unknown_tokens(token):
    assert introspect(token).status_code == 401


def test_introspect_rejects_expired_and_superseded(publish):
    s = new_session()
    with m.Session() as db:
        db.get(m.SessionToken, s["session_id"]).expires_at = m.now() - timedelta(seconds=1); db.commit()
    assert introspect(s["session_token"]).status_code == 401
    s2 = new_session()
    publish(version=V + 1, network={"allow": ["github.com"]})
    assert introspect(s2["session_token"]).status_code == 401


# --- gateway interceptor authorization -------------------------------------------

INTERCEPTOR = {"Authorization": "Bearer interceptor-secret"}


def authorization(name, headers=INTERCEPTOR):
    return client.get(f"/v1/sandboxes/{name}/authorization", headers=headers)


def test_sandbox_authorization_matches_session():
    s = new_session()
    a = authorization(s["sandbox_name"])
    assert a.status_code == 200
    body = a.json()
    assert body["openshell_policy"] == s["openshell_policy"] and body["providers"] == s["providers"]
    assert set(body["providers"].values()) == {"tether-llm", "tether-policy", "github-org"}
    assert body["session_id"] == s["session_id"]


def test_sandbox_authorization_only_for_interceptor():
    s = new_session()
    for h in (USER, ORCHESTRATOR, GATEWAY, {"Authorization": f"Bearer {s['session_token']}"}):
        assert authorization(s["sandbox_name"], headers=h).status_code == 403


def test_unknown_sandbox_not_authorized():
    assert authorization("agent-attacker-made-up").status_code == 404


def test_revoked_or_superseded_sandbox_not_authorized(publish):
    s = new_session()
    with m.Session() as db:
        db.get(m.SessionToken, s["session_id"]).expires_at = m.now() - timedelta(seconds=1); db.commit()
    assert authorization(s["sandbox_name"]).status_code == 404
    s2 = new_session(repo="other-repo")
    publish(version=V + 1, network={"allow": ["pypi.org"]}, github={"org": "your-org", "permissions": {"contents": "write"}})
    assert authorization(s2["sandbox_name"]).status_code == 404


def test_authorization_uses_newest_active_session():
    a, b = new_session(), new_session()
    assert a["sandbox_name"] == b["sandbox_name"]
    assert authorization(a["sandbox_name"]).json()["session_id"] == b["session_id"]


def test_bundle_rejected_when_policy_allows_local_inference_host(publish, monkeypatch):
    # CI cannot know the GPU servers; the API checks the deployment's hosts at publish time.
    monkeypatch.setenv("PLATFORM_LOCAL_INFERENCE_HOSTS", "gpu.company.internal")
    r = publish(expect=422, version=BASE["version"] + 1, network={"allow": ["node7.gpu.company.internal"]}, github=None)
    assert "local inference hosts" in r["detail"]
