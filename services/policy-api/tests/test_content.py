"""Prompt and response content audit (ADR 0001, D5)."""
import json

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from conftest import start_session

import app.main as m

client = TestClient(m.app)
USER = {"Authorization": "Bearer dev:Kim.Dev"}
ADMIN = {"Authorization": "Bearer dev:secops:tether-admins"}
GATEWAY = {"Authorization": "Bearer gateway-secret"}
KEY = Fernet.generate_key().decode()


@pytest.fixture(autouse=True)
def content_key(monkeypatch):
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEY", KEY)


def session():
    r = start_session(client, {"device_id": "mac-1", "agent": "claude", "repo": "git@github.com:co/repo.git"}, USER)
    assert r.status_code == 200, r.text
    return r.json()


def store(s, content="PROMPT-MARKER-7f3a", headers=GATEWAY, **kw):
    body = {"session_id": s["session_id"], "user_id": s["user_id"], "request_id": "req-1", "direction": "request", "content": content, **kw}
    return client.post("/v1/audit/content", json=body, headers=headers)


def events(event_type):
    with m.Session() as db:
        return [e.payload for e in db.query(m.AuditEvent).filter_by(event_type=event_type).order_by(m.AuditEvent.id)]


def test_stored_encrypted_and_event_has_only_reference():
    s = session()
    r = store(s)
    assert r.status_code == 200, r.text
    with m.Session() as db:
        row = db.get(m.LlmContent, r.json()["content_id"])
        assert b"PROMPT-MARKER-7f3a" not in row.ciphertext
        assert Fernet(KEY).decrypt(row.ciphertext) == b"PROMPT-MARKER-7f3a"
    e = events("llm.content")[-1]
    assert "PROMPT-MARKER-7f3a" not in json.dumps(e)
    assert e["unmapped"]["sha256"] == r.json()["sha256"] and e["actor"]["user"]["uid"] == s["user_id"]
    assert e["metadata"]["log_provider"] == "llm-gateway"


@pytest.mark.parametrize("headers", [USER, ADMIN, {"Authorization": "Bearer broker-secret"}])
def test_only_the_llm_gateway_stores(headers):
    assert store(session(), headers=headers).status_code == 403


def test_without_key_storage_is_refused(monkeypatch):
    s = session()
    monkeypatch.delenv("CONTENT_ENCRYPTION_KEY")
    assert store(s).status_code == 503


def test_session_must_belong_to_named_user():
    s = session()
    assert store({**s, "user_id": "someone-else"}).status_code == 404
    assert store({**s, "session_id": "nope"}).status_code == 404


def test_bad_direction_rejected():
    assert store(session(), direction="sideways").status_code == 422


def test_admin_reads_with_reason_and_read_is_audited():
    s = session()
    cid = store(s).json()["content_id"]
    store(s, content="RESPONSE", direction="response")
    assert client.get(f"/v1/audit/content/{cid}", headers=USER, params={"reason": "x"}).status_code == 403
    assert client.get(f"/v1/audit/content/{cid}", headers=ADMIN).status_code == 422  # reason required
    r = client.get(f"/v1/audit/content/{cid}", headers=ADMIN, params={"reason": "INC-7 review"})
    assert r.status_code == 200 and r.json()["content"] == "PROMPT-MARKER-7f3a"
    e = events("audit.content.read")[-1]
    assert e["actor"]["user"]["uid"] == "secops" and e["unmapped"]["content_id"] == cid and e["message"] == "INC-7 review"
    listed = client.get("/v1/audit/content", headers=ADMIN, params={"request_id": "req-1"}).json()["contents"]
    assert [c["direction"] for c in listed] == ["request", "response"] and "content" not in listed[0]
    assert client.get("/v1/audit/content", headers=ADMIN).status_code == 422
