"""Job run results: stored by the orchestrator before the sandbox goes, read by the job's owner."""
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import app.main as m
from test_agent_jobs import ADMIN, KIM, LEE, ORCH, approved_job, events, run

client = TestClient(m.app)
RESULT = {"returncode": 0, "output": "Updated 3 dependencies.", "log": '{"event":"step"}', "diff": "diff --git a/x b/x\n+1\n"}


@pytest.fixture(autouse=True)
def content_key(monkeypatch):
    monkeypatch.setenv("CONTENT_ENCRYPTION_KEY", Fernet.generate_key().decode())


def started_run():
    j = approved_job()
    s = run(j["id"], "manual").json()
    return j["id"], s["session_id"]


def store(job_id, sid, headers=ORCH, **kw):
    return client.post(f"/v1/agent/jobs/{job_id}/runs", json={"session_id": sid, **RESULT, **kw}, headers=headers)


def test_owner_reads_the_answer_log_and_patch():
    job, sid = started_run()
    assert client.get(f"/v1/agent/jobs/{job}/runs", headers=KIM).json()["runs"][0]["status"] == "running"
    r = store(job, sid)
    assert r.status_code == 200 and r.json()["parts"] == ["diff", "log", "output"]
    [listed] = client.get(f"/v1/agent/jobs/{job}/runs", headers=KIM).json()["runs"]
    assert listed["status"] == "finished" and listed["returncode"] == 0 and listed["has_diff"] and "output" not in listed
    v = client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=KIM).json()
    assert (v["output"], v["log"], v["diff"], v["purged"]) == (RESULT["output"], RESULT["log"], RESULT["diff"], False)
    assert events("agent.job.result.read")[-1]["unmapped"] == {"job_id": job, "owner_read": True}


def test_bodies_are_encrypted_and_the_audit_event_has_only_hashes():
    job, sid = started_run()
    store(job, sid)
    with m.Session() as db:
        rows = db.query(m.LlmContent).filter_by(session_id=sid).all()
    assert sorted(r.direction for r in rows) == ["job.diff", "job.log", "job.output"]
    assert all(b"Updated 3" not in r.ciphertext for r in rows)
    e = events("agent.job.result")[-1]
    assert e["unmapped"]["parts"]["output"]["size"] == len(RESULT["output"]) and "Updated 3" not in str(e)
    assert e["status_id"] == 1


def test_failed_run_is_recorded_as_failure():
    job, sid = started_run()
    store(job, sid, returncode=None, timed_out=True, output="")
    v = client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=KIM).json()
    assert v["timed_out"] is True and v["output"] is None and v["diff"].startswith("diff --git")
    assert events("agent.job.result")[-1]["status_id"] == 2


def test_other_people_cannot_see_a_job_or_its_results():
    job, sid = started_run()
    store(job, sid)
    assert client.get(f"/v1/agent/jobs/{job}/runs", headers=LEE).status_code == 404
    assert client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=LEE).status_code == 404
    v = client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=ADMIN).json()  # administrators can
    assert v["output"] == RESULT["output"] and events("agent.job.result.read")[-1]["unmapped"]["owner_read"] is False


def test_only_the_orchestrator_stores_results_once_for_a_session_of_that_job():
    job, sid = started_run()
    assert store(job, sid, headers=KIM).status_code == 403
    assert store(job, sid, headers=ADMIN).status_code == 403
    other = approved_job(name="other")["id"]
    assert store(other, sid).status_code == 404  # session belongs to another job
    assert store(job, "no-such-session").status_code == 404
    assert store(job, sid).status_code == 200
    assert store(job, sid).status_code == 409


def test_without_a_content_key_the_outcome_is_kept_but_not_the_bodies(monkeypatch):
    job, sid = started_run()
    monkeypatch.delenv("CONTENT_ENCRYPTION_KEY")
    r = store(job, sid)
    assert r.status_code == 200 and r.json()["parts"] == []
    v = client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=KIM).json()
    assert v["returncode"] == 0 and v["output"] is None and v["has_output"] is False


def test_bodies_follow_content_retention(monkeypatch):
    job, sid = started_run()
    store(job, sid)
    monkeypatch.setenv("CONTENT_RETENTION_DAYS", "1")
    r = m.purge_contents(m.RETENTION_ACTOR, trigger="cli", at=m.now() + timedelta(days=2))
    assert r["deleted"] == 3
    v = client.get(f"/v1/agent/jobs/{job}/runs/{sid}", headers=KIM).json()
    assert v["status"] == "finished" and v["output"] is None and v["purged"] is True


def test_session_ended_without_a_result_shows_as_ended():
    job, sid = started_run()
    client.post(f"/v1/agent/sessions/{sid}/end", headers=ORCH)
    [listed] = client.get(f"/v1/agent/jobs/{job}/runs", headers=KIM).json()["runs"]
    assert listed["status"] == "ended" and "returncode" not in listed
