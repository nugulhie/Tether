"""Issuance records, kept so the kill switch can revoke credentials that are already out.

GitHub installation tokens can only be revoked with the token itself, so they are stored
encrypted (Fernet, BROKER_ENCRYPTION_KEY). Without a key the broker refuses to issue GitHub
tokens rather than issue ones it could not revoke.
"""
import os
import sqlite3
import threading
import time

from cryptography.fernet import Fernet

_lock = threading.Lock()
_conn = None


def db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(os.environ.get("BROKER_DB", ":memory:"), check_same_thread=False)
        _conn.executescript("""
            CREATE TABLE IF NOT EXISTS issued (session_id TEXT, kind TEXT, role_arn TEXT, secret BLOB, expires_at REAL);
            CREATE INDEX IF NOT EXISTS issued_session ON issued(session_id);
            CREATE TABLE IF NOT EXISTS revoked (session_id TEXT PRIMARY KEY, role_arn TEXT, expires_at REAL);
        """)
    return _conn


def reset():
    global _conn
    _conn = None


def fernet():
    key = os.environ.get("BROKER_ENCRYPTION_KEY")
    return Fernet(key) if key else None


def record_aws(session_id, role_arn, expires_at):
    with _lock:
        db().execute("INSERT INTO issued VALUES (?, 'aws', ?, NULL, ?)", (session_id, role_arn, expires_at))
        db().commit()


def record_github(session_id, token, expires_at):
    with _lock:
        db().execute("INSERT INTO issued VALUES (?, 'github', NULL, ?, ?)", (session_id, fernet().encrypt(token.encode()), expires_at))
        db().commit()


def issued(session_ids):
    q = ",".join("?" * len(session_ids))
    with _lock:
        rows = db().execute(f"SELECT session_id, kind, role_arn, secret, expires_at FROM issued WHERE session_id IN ({q})", session_ids).fetchall()
    out = []
    for sid, kind, role, secret, exp in rows:
        out.append({"session_id": sid, "kind": kind, "role_arn": role, "expires_at": exp,
                    "token": fernet().decrypt(secret).decode() if secret else None})
    return out


def mark_revoked(session_id, role_arn, expires_at):
    with _lock:
        db().execute("INSERT OR REPLACE INTO revoked VALUES (?, ?, ?)", (session_id, role_arn, expires_at))
        db().commit()


def revoked_live(role_arn):
    """Revoked session ids whose credentials could still be valid for this role."""
    with _lock:
        rows = db().execute("SELECT session_id FROM revoked WHERE role_arn = ? AND expires_at > ? ORDER BY session_id", (role_arn, time.time())).fetchall()
    return [r[0] for r in rows]


def forget_github(session_id):
    with _lock:
        db().execute("DELETE FROM issued WHERE session_id = ? AND kind = 'github'", (session_id,))
        db().commit()
