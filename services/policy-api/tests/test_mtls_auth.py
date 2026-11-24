"""AUTH_MODE=mtls: people are identified by client certificates (no SSO).

The mTLS front verifies the certificate against the user CA and forwards its subject; the Policy API
trusts that header only from the front's address and exchanges it for a short-lived bearer token.
"""
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import app.main as m

FRONT = ("172.30.0.20", 50000)
KEY = "k" * 40
SUBJECT = {"x-tether-client-subject": "CN=kim,O=Tether", "x-tether-client-serial": "1A2B"}


@pytest.fixture(autouse=True)
def mtls(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "mtls")
    monkeypatch.setenv("USER_TOKEN_KEY", KEY)
    monkeypatch.setenv("IDENTITY_PROXY_ADDRESSES", "172.30.0.20/32")
    monkeypatch.setenv("ADMIN_USERS", "lee")


def token_for(headers=SUBJECT, peer=FRONT):
    return TestClient(m.app, client=peer).post("/v1/auth/token", headers=headers)


def audit_payloads():
    from sqlalchemy import select
    from app.models import AuditEvent
    with m.Session() as db:
        return [e.payload for e in db.scalars(select(AuditEvent))]


def test_front_certificate_identity_gets_a_short_lived_token():
    r = token_for()
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == "kim" and body["expires_at"] - time.time() <= 3600
    claims = jwt.decode(body["token"], KEY, algorithms=["HS256"], audience="tether")
    assert claims["sub"] == "kim" and claims["groups"] == []
    issued = [e for e in audit_payloads() if e["message"] == "auth.token.issue"]
    assert issued and issued[-1]["unmapped"]["certificate_serial"] == "1A2B"


def test_identity_header_from_any_other_peer_is_refused():
    assert token_for(peer=("172.30.0.11", 50000)).status_code == 403   # another container
    assert token_for(peer=("127.0.0.1", 50000)).status_code == 403     # the host (published port)


@pytest.mark.parametrize("subject", ["", "O=Tether", "CN=Kim,O=Tether", "CN=a,CN=b", "CN=../x"])
def test_unusable_subjects_are_refused(subject):
    assert token_for(headers={"x-tether-client-subject": subject}).status_code == 401


def test_admin_users_get_the_admin_group():
    lee = token_for(headers={"x-tether-client-subject": "CN=lee,O=Tether"}).json()["token"]
    kim = token_for().json()["token"]
    c = TestClient(m.app)
    assert c.get("/v1/admin/guardrails/bypass", headers={"Authorization": f"Bearer {lee}"}).status_code == 200
    assert c.get("/v1/admin/guardrails/bypass", headers={"Authorization": f"Bearer {kim}"}).status_code == 403


def test_forged_expired_and_dev_tokens_are_refused():
    c = TestClient(m.app)
    now = int(time.time())
    forged = jwt.encode({"iss": "tether-policy-api", "aud": "tether", "sub": "lee", "groups": ["tether-admins"],
                         "iat": now, "exp": now + 60}, "x" * 40, algorithm="HS256")
    expired = jwt.encode({"iss": "tether-policy-api", "aud": "tether", "sub": "lee", "groups": ["tether-admins"],
                          "iat": 0, "exp": 100}, KEY, algorithm="HS256")
    for t in (forged, expired, "dev:lee:tether-admins"):
        assert c.get("/v1/admin/guardrails/bypass", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_token_endpoint_only_in_mtls_mode(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "dev")
    assert token_for().status_code == 404


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.setenv("USER_TOKEN_KEY", "short")
    assert token_for().status_code == 500
