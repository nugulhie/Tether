"""Content retention and legal hold (ADR 0001, D5): bodies are destroyed after CONTENT_RETENTION_DAYS
unless an open hold covers their user, session or job."""
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

import app.main as m
import app.purge as cli

client = TestClient(m.app)
USER = {"Authorization": "Bearer dev:Kim.Dev"}
ADMIN = {"Authorization": "Bearer dev:secops:agent-security-admins"}
GATEWAY = {"Authorization": "Bearer gateway-secret"}
SIEM = {"Authorization": "Bearer siem-secret"}
KEY = Fernet.generate_key().decode()
MARKER = "SECRET-PROMPT-MARKER-91c2"
T = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
SERVICE_DIR = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def content_env(monkeypatch):
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEY", KEY)
    for k in ("CONTENT_RETENTION_DAYS", "CONTENT_PURGE_INTERVAL_SECONDS", "CONTENT_PURGE_BATCH_SIZE"):
        monkeypatch.delenv(k, raising=False)


def put(created_at, *, session_id=None, user="kim", job=None):
    """One stored body (and its session) created at the given time."""
    sid = session_id or str(uuid.uuid4())
    with m.Session() as db:
        if not db.get(m.AgentSession, sid):
            db.add(m.AgentSession(id=sid, user_id=user, device_id="mac-1", agent="local" if job else "claude", repo="git@github.com:co/repo.git",
                                  environment="development", policy_id="p", policy_version=1, sandbox_name="sb", job_id=job))
        cid = str(uuid.uuid4())
        db.add(m.LlmContent(id=cid, session_id=sid, request_id="req-1", direction="request", sha256="0" * 64, size=len(MARKER),
                            ciphertext=Fernet(KEY).encrypt(MARKER.encode()), created_at=created_at))
        db.commit()
    return cid


def exists(cid):
    with m.Session() as db:
        return db.get(m.LlmContent, cid) is not None


def events(event_type):
    with m.Session() as db:
        return [e.payload for e in db.query(m.AuditEvent).filter_by(event_type=event_type).order_by(m.AuditEvent.id)]


def purge(**kw):
    return m.purge_contents(m.RETENTION_ACTOR, trigger="test", **{"at": T, **kw})


def hold(scope, value, headers=ADMIN, reason="LIT-2026-14 preservation notice"):
    return client.post("/v1/admin/audit/content/holds", json={"scope": scope, "value": value, "reason": reason}, headers=headers)


def test_expiry_boundary_is_exact():
    cutoff = T - timedelta(days=90)
    old = put(cutoff - timedelta(seconds=1))
    at_cutoff = put(cutoff)
    young = put(cutoff + timedelta(seconds=1))
    r = purge()
    assert r["deleted"] == 1 and r["expired"] == 1 and r["retention_days"] == 90 and r["cutoff"] == cutoff.isoformat()
    assert not exists(old) and exists(at_cutoff) and exists(young)


def test_retention_is_configurable(monkeypatch):
    monkeypatch.setenv("CONTENT_RETENTION_DAYS", "7")
    gone, kept = put(T - timedelta(days=8)), put(T - timedelta(days=6))
    assert purge()["deleted"] == 1
    assert not exists(gone) and exists(kept)


@pytest.mark.parametrize("value", ["0", "-5", "abc", "1.5"])
def test_bad_retention_is_refused_at_startup(monkeypatch, value):
    monkeypatch.setenv("CONTENT_RETENTION_DAYS", value)
    with pytest.raises(ValueError, match="CONTENT_RETENTION_DAYS"):
        m.content_retention_days()
    with pytest.raises(ValueError):
        with TestClient(m.app):
            pass
    cid = put(T - timedelta(days=1000))
    with pytest.raises(ValueError):
        purge()
    assert exists(cid)


def test_bad_purge_interval_is_refused_at_startup(monkeypatch):
    monkeypatch.setenv("CONTENT_PURGE_INTERVAL_SECONDS", "-1")
    with pytest.raises(ValueError, match="CONTENT_PURGE_INTERVAL_SECONDS"):
        with TestClient(m.app):
            pass


@pytest.mark.parametrize("scope", ["user", "session", "job"])
def test_hold_by_each_scope_spares_only_its_content(scope):
    old = T - timedelta(days=200)
    sid = str(uuid.uuid4())
    held = put(old, session_id=sid, user="lee", job="job-1" if scope == "job" else None)
    other = put(old, user="park", job="job-2" if scope == "job" else None)
    value = {"user": "lee", "session": sid, "job": "job-1"}[scope]
    r = hold(scope, value)
    assert r.status_code == 200, r.text
    res = purge()
    assert (res["expired"], res["held"], res["deleted"], res["open_holds"]) == (2, 1, 1, 1)
    assert exists(held) and not exists(other)
    e = events("audit.content.purge")[-1]["unmapped"]
    assert e["held"] == 1 and e["deleted"] == 1 and e["cutoff"] == (T - timedelta(days=90)).isoformat()


def test_released_hold_then_purged():
    cid = put(T - timedelta(days=200), user="lee")
    h = hold("user", "lee").json()
    assert purge()["deleted"] == 0 and exists(cid)
    listed = client.get("/v1/admin/audit/content/holds", headers=ADMIN).json()["holds"]
    assert [x["id"] for x in listed] == [h["id"]]
    assert client.delete(f"/v1/admin/audit/content/holds/{h['id']}", headers=ADMIN).status_code == 422  # reason required
    r = client.delete(f"/v1/admin/audit/content/holds/{h['id']}", headers=ADMIN, params={"reason": "matter closed"})
    assert r.status_code == 200 and r.json()["released_by"] == "secops" and r.json()["released_at"]
    assert client.delete(f"/v1/admin/audit/content/holds/{h['id']}", headers=ADMIN, params={"reason": "again"}).status_code == 404
    assert client.get("/v1/admin/audit/content/holds", headers=ADMIN).json()["holds"] == []
    assert len(client.get("/v1/admin/audit/content/holds", headers=ADMIN, params={"include_released": True}).json()["holds"]) == 1
    res = purge()
    assert res["deleted"] == 1 and res["held"] == 0 and not exists(cid)
    start, end = events("audit.content.hold.start")[-1], events("audit.content.hold.end")[-1]
    assert start["actor"]["user"]["uid"] == "secops" and start["unmapped"]["scope"] == "user" and start["message"] == "LIT-2026-14 preservation notice"
    assert end["unmapped"]["release_reason"] == "matter closed" and end["activity_name"] == "Delete"


@pytest.mark.parametrize("body", [{"scope": "user", "value": "lee"}, {"scope": "user", "value": "lee", "reason": ""},
                                  {"scope": "device", "value": "mac-1", "reason": "x"}, {"scope": "user", "value": "", "reason": "x"}])
def test_hold_validation(body):
    assert client.post("/v1/admin/audit/content/holds", json=body, headers=ADMIN).status_code == 422


def test_dry_run_counts_and_deletes_nothing():
    a, b = put(T - timedelta(days=100), user="lee"), put(T - timedelta(days=100))
    put(T - timedelta(days=1))
    hold("user", "lee")
    r = purge(dry_run=True)
    assert (r["dry_run"], r["expired"], r["held"], r["deleted"], r["would_delete"]) == (True, 2, 1, 0, 1)
    assert exists(a) and exists(b)
    e = events("audit.content.purge")[-1]
    assert e["unmapped"]["dry_run"] is True and e["message"].startswith("dry run")


def test_admin_purge_endpoint_and_dry_run():
    old = put(m.now() - timedelta(days=91))
    young = put(m.now() - timedelta(days=89))
    r = client.post("/v1/admin/audit/content/purge", headers=ADMIN, params={"dry_run": True})
    assert r.status_code == 200 and r.json()["would_delete"] == 1 and exists(old)
    r = client.post("/v1/admin/audit/content/purge", headers=ADMIN)
    assert r.status_code == 200 and r.json()["deleted"] == 1 and r.json()["trigger"] == "api"
    assert not exists(old) and exists(young)
    assert events("audit.content.purge")[-1]["actor"]["user"]["uid"] == "secops"


@pytest.mark.parametrize("headers", [USER, GATEWAY, SIEM, {"Authorization": "Bearer orchestrator-secret"}])
def test_non_admins_cannot_hold_or_purge(headers):
    cid = put(m.now() - timedelta(days=200))
    h = hold("user", "kim").json()
    assert hold("user", "kim", headers=headers).status_code == 403
    assert client.get("/v1/admin/audit/content/holds", headers=headers).status_code == 403
    assert client.delete(f"/v1/admin/audit/content/holds/{h['id']}", headers=headers, params={"reason": "x"}).status_code == 403
    assert client.post("/v1/admin/audit/content/purge", headers=headers).status_code == 403
    assert exists(cid)


def test_audit_events_never_carry_content():
    cid = put(T - timedelta(days=200), user="lee")
    put(T - timedelta(days=200))
    h = hold("user", "lee").json()
    purge(dry_run=True); purge()
    client.delete(f"/v1/admin/audit/content/holds/{h['id']}", headers=ADMIN, params={"reason": "closed"})
    purge()
    for t in ("audit.content.purge", "audit.content.hold.start", "audit.content.hold.end"):
        for e in events(t):
            dumped = json.dumps(e)
            assert MARKER not in dumped and cid not in dumped and "ciphertext" not in dumped
    assert len(events("audit.content.purge")) == 3  # exactly one per run


def test_purged_content_reads_404_and_listing_still_works():
    from conftest import start_session
    s = start_session(client, {"device_id": "mac-1", "agent": "claude", "repo": "git@github.com:co/repo.git"}, USER).json()
    body = {"session_id": s["session_id"], "user_id": s["user_id"], "request_id": "req-9", "direction": "request", "content": MARKER}
    old = client.post("/v1/audit/content", json=body, headers=GATEWAY).json()["content_id"]
    new = client.post("/v1/audit/content", json={**body, "direction": "response"}, headers=GATEWAY).json()["content_id"]
    with m.Session() as db:
        db.get(m.LlmContent, old).created_at = m.now() - timedelta(days=120); db.commit()
    assert client.post("/v1/admin/audit/content/purge", headers=ADMIN).json()["deleted"] == 1
    r = client.get(f"/v1/audit/content/{old}", headers=ADMIN, params={"reason": "INC-1"})
    assert r.status_code == 404 and "purged" in r.json()["detail"]
    assert client.get(f"/v1/audit/content/{new}", headers=ADMIN, params={"reason": "INC-1"}).json()["content"] == MARKER
    listed = client.get("/v1/audit/content", headers=ADMIN, params={"request_id": "req-9"}).json()["contents"]
    assert [c["content_id"] for c in listed] == [new]
    # The reference and hash in the original llm.content event outlive the body.
    assert any(e["unmapped"]["content_id"] == old for e in events("llm.content"))


def test_purge_is_idempotent_and_batched():
    ids = [put(T - timedelta(days=100 + i)) for i in range(5)]
    kept = put(T - timedelta(days=10))
    r = purge(batch_size=2)
    assert r["deleted"] == 5 and r["skipped_other"] == 0
    assert not any(exists(c) for c in ids) and exists(kept)
    r = purge(batch_size=2)
    assert (r["expired"], r["deleted"]) == (0, 0)


def test_hold_placed_after_scan_still_wins():
    """The hold check is part of the DELETE, so a hold committed between a purge's scan and its delete
    (or a concurrent purge run) cannot lose content or double-count it."""
    cid = put(T - timedelta(days=200), user="lee")
    hold("user", "lee")
    with m.Session() as db:
        n = db.execute(delete(m.LlmContent).where(m.LlmContent.id.in_([cid]), ~m.held()).execution_options(synchronize_session=False)).rowcount
        db.commit()
    assert n == 0 and exists(cid)


def test_concurrent_run_counts_rows_once(monkeypatch):
    """A row another run deleted first is reported as skipped_other, not deleted twice."""
    cid = put(T - timedelta(days=200))
    real = m.held

    def racing_held():
        with m.Session() as db:  # another purge deletes the row between this run's scan and delete
            db.execute(delete(m.LlmContent).where(m.LlmContent.id == cid)); db.commit()
        return real()
    monkeypatch.setattr(m, "held", racing_held)
    r = purge()
    assert (r["expired"], r["deleted"], r["skipped_other"]) == (1, 0, 1)


def test_failed_purge_is_still_audited(monkeypatch):
    put(T - timedelta(days=200))
    monkeypatch.setattr(m, "held", lambda: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        purge()
    e = events("audit.content.purge")[-1]
    assert e["status_id"] == 2 and e["unmapped"]["error"] == "ZeroDivisionError"


def test_cli_in_process(capsys, monkeypatch):
    old = put(m.now() - timedelta(days=100))
    assert cli.main(["--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["would_delete"] == 1 and exists(old)
    assert cli.main(["--batch-size", "1"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["deleted"] == 1 and out["trigger"] == "cli" and not exists(old)
    assert events("audit.content.purge")[-1]["actor"]["user"]["uid"] == "content-retention"
    monkeypatch.setenv("CONTENT_RETENTION_DAYS", "0")
    assert cli.main([]) == 2
    assert "CONTENT_RETENTION_DAYS" in capsys.readouterr().err


def test_cli_as_a_process(tmp_path):
    """`python -m app.purge` against a real (file) database, as a CronJob would run it."""
    from sqlalchemy import create_engine
    from app.db import migrate
    url = f"sqlite:///{tmp_path / 'policy.db'}"
    engine = create_engine(url)
    migrate(bind=engine)
    bound = m.Session.kw["bind"]
    m.Session.configure(bind=engine)
    try:
        old, young = put(m.now() - timedelta(days=95)), put(m.now() - timedelta(days=5))
    finally:
        m.Session.configure(bind=bound)
    run = lambda *a, **e: subprocess.run([sys.executable, "-m", "app.purge", *a], cwd=SERVICE_DIR, capture_output=True, text=True,
                                         env={**os.environ, "DATABASE_URL": url, **e})
    bad = run(CONTENT_RETENTION_DAYS="0")
    assert bad.returncode == 2 and "CONTENT_RETENTION_DAYS" in bad.stderr
    p = run()
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["deleted"] == 1
    assert '"audit.content.purge"' in p.stderr and MARKER not in p.stderr  # OCSF line on the audit log
    with engine.connect() as c:
        assert [r[0] for r in c.execute(select(m.LlmContent.id))] == [young]
    engine.dispose()


def test_in_process_loop_purges_when_enabled(monkeypatch):
    old = put(m.now() - timedelta(days=100))
    monkeypatch.setenv("CONTENT_PURGE_INTERVAL_SECONDS", "3600")
    with TestClient(m.app):
        for _ in range(100):
            if events("audit.content.purge"):
                break
            time.sleep(0.05)
    e = events("audit.content.purge")
    assert len(e) == 1 and e[0]["unmapped"]["trigger"] == "schedule" and not exists(old)


def test_loop_is_off_by_default():
    old = put(m.now() - timedelta(days=100))
    with TestClient(m.app):
        time.sleep(0.2)
    assert exists(old) and events("audit.content.purge") == []
