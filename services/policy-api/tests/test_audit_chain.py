"""Audit hash chain: modifying, deleting or reordering an event is detectable."""
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update

import app.main as m
from app import audit_chain
from app.auth import Principal
from app.models import AuditEvent

client = TestClient(m.app)
ADMIN = {"Authorization": "Bearer dev:secops:tether-admins"}
ACTOR = Principal(kind="service", user_id="test")


def write(n):
    with m.Session() as db:
        for i in range(n):
            m.record(db, "policy.publish", ACTOR, source="test", data={"i": i})
        db.commit()


def ids():
    with m.Session() as db:
        return list(db.scalars(select(AuditEvent.id).where(AuditEvent.hash.is_not(None)).order_by(AuditEvent.id)))


def verify():
    with m.Session() as db:
        return audit_chain.verify(db)


def test_events_are_chained_and_verify():
    write(5)
    r = verify()
    assert r["ok"] and r["events"] >= 5 and r["head_id"] == ids()[-1]
    with m.Session() as db:
        first, second = db.scalars(select(AuditEvent).where(AuditEvent.hash.is_not(None)).order_by(AuditEvent.id).limit(2))
        assert first.prev_hash == audit_chain.GENESIS and second.prev_hash == first.hash


def test_modified_event_is_detected():
    write(5)
    target = ids()[2]
    with m.Session() as db:
        e = db.get(AuditEvent, target)
        e.payload = {**e.payload, "message": "nothing happened"}
        db.commit()
    r = verify()
    assert not r["ok"] and r["broken_at"] == target and "modified" in r["reason"]


def test_deleted_event_is_detected():
    write(5)
    victim = ids()[2]
    with m.Session() as db:
        db.execute(delete(AuditEvent).where(AuditEvent.id == victim))
        db.commit()
    r = verify()
    assert not r["ok"] and r["broken_at"] == ids()[2] and "deleted" in r["reason"]


def test_unhashed_event_inside_the_chain_is_detected():
    write(3)
    with m.Session() as db:
        db.execute(update(AuditEvent).where(AuditEvent.id == ids()[1]).values(hash=None))
        db.commit()
    assert not verify()["ok"]


def test_several_events_in_one_transaction_link_in_order():
    with m.Session() as db:
        a = audit_chain.append(db, "policy.publish", {"n": 1})
        b = audit_chain.append(db, "policy.publish", {"n": 2})
        assert b.prev_hash == a.hash
        db.commit()
    assert verify()["ok"]


def test_chain_endpoint_is_admin_only():
    write(1)
    r = client.get("/v1/admin/audit/chain", headers=ADMIN)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert client.get("/v1/admin/audit/chain", headers={"Authorization": "Bearer dev:kim"}).status_code == 403
    assert client.get("/v1/admin/audit/chain", headers={"Authorization": "Bearer siem-secret"}).status_code == 200
