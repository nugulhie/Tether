"""Guardrail break-glass (ADR 0001, D4) and what the LLM gateway learns from introspection."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from conftest import start_session

import app.main as m

client = TestClient(m.app)
USER = {"Authorization": "Bearer dev:Kim.Dev"}
ADMIN = {"Authorization": "Bearer dev:secops:agent-security-admins"}
GATEWAY = {"Authorization": "Bearer gateway-secret"}
SIEM = {"Authorization": "Bearer siem-secret"}


def session(headers=USER):
    r = start_session(client, {"device_id": "mac-1", "agent": "claude", "repo": "git@github.com:co/repo.git"}, headers)
    assert r.status_code == 200, r.text
    return r.json()


def introspect(s):
    r = client.post("/v1/sessions/introspect", json={"session_token": s["session_token"]}, headers=GATEWAY)
    assert r.status_code == 200, r.text
    return r.json()


def start(headers=ADMIN, **body):
    return client.post("/v1/admin/guardrails/bypass", json={"scope": "all", "reason": "INC-9 guardrail model down", "ttl_seconds": 600, **body}, headers=headers)


def events(event_type):
    with m.Session() as db:
        return [e.payload for e in db.query(m.AuditEvent).filter_by(event_type=event_type).order_by(m.AuditEvent.id)]


def test_introspect_carries_policy_guardrails():
    i = introspect(session())
    assert i["guardrails"]["input"]["secrets"] is True and i["guardrail_bypasses"] == []


@pytest.mark.parametrize("headers", [USER, GATEWAY, SIEM])
def test_only_admins_start(headers):
    assert start(headers=headers).status_code == 403


def test_bypass_lifecycle_is_audited():
    s = session()
    r = start()
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["created_by"] == "secops" and b["scope"] == "all"
    assert events("guardrail.bypass.start")[-1]["message"] == "INC-9 guardrail model down"
    assert [x["id"] for x in introspect(s)["guardrail_bypasses"]] == [b["id"]]
    assert [x["id"] for x in client.get("/v1/admin/guardrails/bypass", headers=SIEM).json()["bypasses"]] == [b["id"]]
    assert client.delete(f"/v1/admin/guardrails/bypass/{b['id']}", headers=ADMIN).status_code == 422  # reason required
    assert client.delete(f"/v1/admin/guardrails/bypass/{b['id']}", headers=ADMIN, params={"reason": "fixed"}).status_code == 200
    assert introspect(s)["guardrail_bypasses"] == []
    e = events("guardrail.bypass.end")[-1]
    assert e["unmapped"]["ended_by"] == "secops" and e["unmapped"]["end_reason"] == "fixed"
    assert client.delete(f"/v1/admin/guardrails/bypass/{b['id']}", headers=ADMIN, params={"reason": "again"}).status_code == 404


@pytest.mark.parametrize("body", [
    {"ttl_seconds": 14401},                  # longer than the maximum
    {"ttl_seconds": 0},
    {"scope": "session"},                    # target missing
    {"scope": "all", "target": "x"},         # target not allowed for all
    {"scope": "forever"},
    {"reason": ""},
])
def test_invalid_bypass_rejected(body):
    assert start(**body).status_code == 422


def test_max_ttl_is_configurable(monkeypatch):
    monkeypatch.setenv("GUARDRAIL_BYPASS_MAX_SECONDS", "300")
    assert start(ttl_seconds=301).status_code == 422
    assert start(ttl_seconds=300).status_code == 200


def test_scopes():
    kim, lee = session(), session({"Authorization": "Bearer dev:Lee.Dev"})
    start(scope="session", target=kim["session_id"])
    start(scope="user", target="Lee.Dev")
    start(scope="policy", target="other-policy")
    start(scope="model", target="company-coder-*")
    scopes = lambda s: sorted(b["scope"] for b in introspect(s)["guardrail_bypasses"])
    assert scopes(kim) == ["model", "session"]
    assert scopes(lee) == ["model", "user"]


def test_expired_bypass_closes_itself_with_an_event():
    s = session()
    bid = start().json()["id"]
    with m.Session() as db:
        b = db.get(m.GuardrailBypass, bid)
        b.expires_at = m.now() - timedelta(seconds=1)
        db.commit()
    assert introspect(s)["guardrail_bypasses"] == []
    e = events("guardrail.bypass.end")[-1]
    assert e["unmapped"]["id"] == bid and e["unmapped"]["ended_by"] == "expired"
    assert client.get("/v1/admin/guardrails/bypass", headers=ADMIN).json()["bypasses"] == []
    assert len(events("guardrail.bypass.end")) == 1  # closed once


def test_gateway_may_report_guardrail_events_but_users_may_not():
    s = session()
    body = {"event_type": "guardrail.block", "session_id": s["session_id"], "user_id": s["user_id"], "data": {"direction": "input"}}
    assert client.post("/v1/audit/events", json=body, headers=GATEWAY).status_code == 200
    assert client.post("/v1/audit/events", json=body, headers=USER).status_code == 422
    assert client.post("/v1/audit/events", json={**body, "event_type": "guardrail.bypass.start"}, headers=GATEWAY).status_code == 422
