"""Content key rotation (ADR 0002, P3): a keyring, key ids on rows, rekey, and what breaks if a key goes."""
import json

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import app.main as m
from app import content_keys, rekey
from test_content import ADMIN, USER, events, session, store
from test_job_results import started_run, store as store_result
from test_agent_jobs import KIM

client = TestClient(m.app)
OLD, NEW = Fernet.generate_key().decode(), Fernet.generate_key().decode()


@pytest.fixture(autouse=True)
def only_legacy_key(monkeypatch):
    for n in ("CONTENT_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS_FILE"):
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEY", OLD)


def rotate(monkeypatch, value=f"2026-11:{NEW},default:{OLD}"):
    monkeypatch.delenv("CONTENT_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS", value)


def read(cid):
    return client.get(f"/v1/audit/content/{cid}", headers=ADMIN, params={"reason": "key test"})


def row(cid):
    with m.Session() as db:
        return db.get(m.LlmContent, cid)


def status():
    r = client.get("/v1/admin/audit/content/keys", headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def test_single_legacy_key_is_the_default_id():
    cid = store(session()).json()["content_id"]
    assert row(cid).key_id == "default"
    assert read(cid).json()["content"] == "PROMPT-MARKER-7f3a"


def test_new_key_encrypts_and_old_rows_stay_readable(monkeypatch):
    s = session()
    old = store(s).json()["content_id"]
    rotate(monkeypatch)
    new = store(s, content="AFTER-ROTATION").json()["content_id"]
    assert row(new).key_id == "2026-11" and Fernet(NEW).decrypt(row(new).ciphertext) == b"AFTER-ROTATION"
    assert read(old).json()["content"] == "PROMPT-MARKER-7f3a"
    assert read(new).json()["content"] == "AFTER-ROTATION"
    st = status()
    assert st["active"] == "2026-11" and st["rows_by_key"] == {"default": 1, "2026-11": 1}
    assert st["removable"] == [] and st["missing"] == [] and OLD not in json.dumps(st) and NEW not in json.dumps(st)


def test_rekey_moves_everything_and_the_old_key_can_go(monkeypatch):
    s = session()
    cids = [store(s, content=f"BODY-{i}").json()["content_id"] for i in range(5)]
    sha = {c: row(c).sha256 for c in cids}
    rotate(monkeypatch)
    dry = client.post("/v1/admin/audit/content/rekey", headers=ADMIN, params={"dry_run": True}).json()
    assert dry["would_rekey"] == 5 and dry["rekeyed"] == 0 and row(cids[0]).key_id == "default"
    out = m.rekey_contents(m.REKEY_ACTOR, trigger="cli", batch_size=2)  # several batches
    assert (out["candidates"], out["rekeyed"], out["failed"], out["missing_keys"]) == (5, 5, 0, {})
    assert out["remaining"] == {"2026-11": 5} and status()["removable"] == ["default"]
    assert {c: row(c).sha256 for c in cids} == sha  # plaintext hashes, and so audit references, unchanged
    rotate(monkeypatch, f"2026-11:{NEW}")  # old key removed
    assert [read(c).json()["content"] for c in cids] == [f"BODY-{i}" for i in range(5)]
    e = events("audit.content.rekey")[-1]
    assert e["unmapped"]["rekeyed"] == 5 and e["activity_name"] == "Update" and NEW not in json.dumps(e)
    assert m.rekey_contents(m.REKEY_ACTOR, trigger="cli")["candidates"] == 0  # idempotent


def test_removing_a_key_too_early_shows_and_is_not_hidden(monkeypatch):
    cid = store(session()).json()["content_id"]
    rotate(monkeypatch, f"2026-11:{NEW}")  # "default" dropped before rekey
    r = read(cid)
    assert r.status_code == 500 and "'default'" in r.json()["detail"]
    assert status()["missing"] == ["default"]
    out = m.rekey_contents(m.REKEY_ACTOR, trigger="cli")
    assert out["missing_keys"] == {"default": 1} and out["rekeyed"] == 0
    assert events("audit.content.rekey")[-1]["status_id"] == 2  # failure
    assert rekey.main([]) == 1


def test_wrong_key_under_the_right_id_is_counted_as_failed(monkeypatch):
    cid = store(session()).json()["content_id"]
    rotate(monkeypatch, f"2026-11:{NEW},default:{Fernet.generate_key().decode()}")
    assert read(cid).status_code == 500
    out = m.rekey_contents(m.REKEY_ACTOR, trigger="cli")
    assert out["failed"] == 1 and row(cid).key_id == "default"


def test_keys_file(monkeypatch, tmp_path):
    f = tmp_path / "keys"
    f.write_text(f"# rotated 2026-11\n2026-11:{NEW}\ndefault:{OLD}\n")
    monkeypatch.delenv("CONTENT_ENCRYPTION_KEY")
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS_FILE", str(f))
    cid = store(session()).json()["content_id"]
    assert row(cid).key_id == "2026-11" and status()["configured"] == ["2026-11", "default"]


@pytest.mark.parametrize("value, error", [
    ("nokeyid", "id:key"),
    (f"a:{NEW},a:{OLD}", "twice"),
    (f"bad id:{NEW}", "invalid content key id"),
    ("a:not-a-fernet-key", "not a valid Fernet key"),
])
def test_malformed_keys_refuse_writes_and_startup(monkeypatch, value, error):
    s = session()
    rotate(monkeypatch, value)
    r = store(s)
    assert r.status_code == 503 and error in r.json()["detail"] and NEW not in r.json()["detail"]
    with pytest.raises(content_keys.KeyringError):
        content_keys.load()
    assert rekey.main([]) == 2


def test_missing_keys_file_is_a_configuration_error(monkeypatch, tmp_path):
    monkeypatch.delenv("CONTENT_ENCRYPTION_KEY")
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEYS_FILE", str(tmp_path / "absent"))
    with pytest.raises(content_keys.KeyringError, match="cannot read"):
        content_keys.load()


def test_job_results_use_the_ring_and_a_bad_ring_is_not_silently_skipped(monkeypatch):
    job, sid = started_run()
    rotate(monkeypatch)
    assert store_result(job, sid).status_code == 200
    v = client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=KIM).json()
    assert v["output"] == "Updated 3 dependencies."
    with m.Session() as db:
        assert {r.key_id for r in db.query(m.LlmContent).filter_by(session_id=sid)} == {"2026-11"}
    job2, sid2 = started_run()
    rotate(monkeypatch, "broken")
    assert store_result(job2, sid2).status_code == 503  # misconfigured, not "no key": bodies are not dropped quietly


def test_only_admins_see_key_status_and_rekey():
    assert client.get("/v1/admin/audit/content/keys", headers=USER).status_code == 403
    assert client.post("/v1/admin/audit/content/rekey", headers=USER).status_code == 403


def test_upgrade_keeps_existing_rows_readable_as_default(tmp_path):
    """A database at 0011 with stored bodies: after the upgrade those rows are on "default"."""
    from alembic import command
    from sqlalchemy import create_engine, text
    from app.db import alembic_config
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "0011")
        conn.execute(text("INSERT INTO llm_contents (id, session_id, request_id, direction, sha256, size, truncated, ciphertext, created_at) "
                          "VALUES ('c1', 's1', 'r1', 'request', 'x', 4, 0, :ct, '2026-11-01 00:00:00')"), {"ct": Fernet(OLD).encrypt(b"BODY")})
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
        [(key_id, ct)] = conn.execute(text("SELECT key_id, ciphertext FROM llm_contents")).all()
    assert key_id == "default"
    assert content_keys.Keyring([("2026-11", NEW), ("default", OLD)]).decrypt(key_id, ct) == b"BODY"
