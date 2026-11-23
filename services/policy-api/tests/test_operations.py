"""Incident-response kill switch and SIEM pull."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from conftest import start_session

import app.main as m

client = TestClient(m.app)
USER = {"Authorization": "Bearer dev:kim"}
ADMIN = {"Authorization": "Bearer dev:secops:agent-security-admins"}
SIEM = {"Authorization": "Bearer siem-secret"}
SESSION = {"device_id": "mac-1", "agent": "claude", "repo": "git@github.com:co/repo.git"}


def events(event_type):
    r = client.get("/v1/audit/events", headers=SIEM, params={"limit": 5000})
    return [e for e in r.json()["events"] if e["metadata"]["event_code"] == event_type]


def new_session(headers=USER, **body):
    return start_session(client, {**SESSION, **body}, headers)


# --- kill switch -------------------------------------------------------------

def test_revoke_requires_admin():
    for h in (USER, SIEM):
        assert client.post("/v1/admin/sessions/revoke", headers=h, json={"all": True, "reason": "x"}).status_code == 403


@pytest.mark.parametrize("body", [{"reason": "x"}, {"all": True, "user_id": "kim", "reason": "x"}, {"all": True, "reason": ""}])
def test_revoke_requires_explicit_scope(body):
    assert client.post("/v1/admin/sessions/revoke", headers=ADMIN, json=body).status_code == 422


def test_revoke_by_user_cuts_off_sessions():
    kim = new_session().json()
    lee = new_session({"Authorization": "Bearer dev:lee"}).json()
    r = client.post("/v1/admin/sessions/revoke", headers=ADMIN, json={"user_id": "kim", "reason": "INC-42 suspected exfiltration"})
    assert r.json()["revoked"] == 1 and r.json()["sessions"][0]["sandbox_name"] == kim["sandbox_name"]
    check = lambda s: client.post("/v1/permissions/check", headers={"Authorization": f"Bearer {s['session_token']}"}, json={"action": "network_connect", "resource": "github.com"})
    assert check(kim).status_code == 401
    assert check(lee).status_code == 200
    assert client.get(f"/v1/agent/sessions/{kim['session_id']}", headers=USER).status_code == 410  # broker refuses
    e = events("session.revoke")[-1]
    assert (e["actor"]["user"]["uid"], e["message"], e["unmapped"]["count"]) == ("secops", "INC-42 suspected exfiltration", 1)
    # Revoking again changes nothing.
    assert client.post("/v1/admin/sessions/revoke", headers=ADMIN, json={"user_id": "kim", "reason": "again"}).json()["revoked"] == 0


def test_revoke_by_device_and_all():
    new_session(); new_session(device_id="mac-9")
    assert client.post("/v1/admin/sessions/revoke", headers=ADMIN, json={"device_id": "mac-9", "reason": "lost laptop"}).json()["revoked"] == 1
    assert client.post("/v1/admin/sessions/revoke", headers=ADMIN, json={"all": True, "reason": "global stop"}).json()["revoked"] == 1


# --- SIEM pull -----------------------------------------------------------------

def test_siem_pull_pages_in_order():
    for _ in range(3):
        new_session()
    first = client.get("/v1/audit/events", headers=SIEM, params={"limit": 2}).json()
    rest = client.get("/v1/audit/events", headers=SIEM, params={"after_id": first["next_after_id"]}).json()
    ids = [e["id"] for e in first["events"] + rest["events"]]
    assert ids == sorted(ids) and len(set(ids)) == len(ids) >= 4  # policy.publish + 3 session.create
    assert client.get("/v1/audit/events", headers=SIEM, params={"after_id": rest["next_after_id"]}).json()["events"] == []


def test_siem_pull_access():
    assert client.get("/v1/audit/events", headers=USER).status_code == 403
    assert client.get("/v1/audit/events", headers={"Authorization": "Bearer broker-secret"}).status_code == 403
    assert client.get("/v1/audit/events", headers=ADMIN).status_code == 200

