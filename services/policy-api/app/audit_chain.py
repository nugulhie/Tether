"""Hash chain over the audit log (tamper evidence).

Every event stores sha256(prev_hash | event_type | canonical payload). Rewriting or deleting an event
breaks every hash after it, so a copy of a recent chain head kept off the server (the administrator's
backup, infra/staging/70-backup.sh) shows whether history was changed. It does not stop someone with
database access from rewriting the whole chain consistently; the off-server head is what catches that.

    python -m app.audit_chain            verify; prints JSON {"ok", "events", "head_id", "head_hash", ...}
    python -m app.audit_chain <id>       print the stored hash of event <id> (for comparing with a backup)
"""
import hashlib
import json
import sys

from sqlalchemy import select, text

from .models import AuditEvent

GENESIS = "0" * 64
LOCK_KEY = 0x7E7E_A0D1  # pg_advisory_xact_lock key serializing audit writes


def event_hash(prev_hash: str, event_type: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(f"{prev_hash}|{event_type}|{canonical}".encode()).hexdigest()


def append(db, event_type: str, payload: dict) -> AuditEvent:
    """Add an event linked to the latest one. Writers are serialized on PostgreSQL (transaction-scoped
    advisory lock, released at commit), so two transactions never link to the same predecessor."""
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": LOCK_KEY})
    prev = db.scalar(select(AuditEvent.hash).where(AuditEvent.hash.is_not(None)).order_by(AuditEvent.id.desc()).limit(1)) or GENESIS
    e = AuditEvent(event_type=event_type, payload=payload, prev_hash=prev, hash=event_hash(prev, event_type, payload))
    db.add(e)
    db.flush()  # later appends in this transaction link to this one
    return e


def verify(db) -> dict:
    """Walk the chain in id order. Rows from before the chain existed (NULL hash) may only precede it."""
    prev, count, head, started = GENESIS, 0, None, False
    for e in db.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        if e.hash is None:
            if started:
                return {"ok": False, "events": count, "broken_at": e.id, "reason": "unhashed event inside the chain"}
            continue
        started = True
        if e.prev_hash != prev:
            return {"ok": False, "events": count, "broken_at": e.id, "reason": "link to previous event does not match (deleted or reordered)"}
        if event_hash(prev, e.event_type, e.payload) != e.hash:
            return {"ok": False, "events": count, "broken_at": e.id, "reason": "event content does not match its hash (modified)"}
        prev, count, head = e.hash, count + 1, e.id
    return {"ok": True, "events": count, "head_id": head, "head_hash": prev if head else None}


def main(argv):
    from .db import Session
    with Session() as db:
        if argv:
            e = db.get(AuditEvent, int(argv[0]))
            print(e.hash if e and e.hash else "")
            return 0 if e and e.hash else 1
        result = verify(db)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
