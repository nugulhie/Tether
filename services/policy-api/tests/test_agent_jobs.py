"""Local-agent jobs (ADR 0001, D1): administrator approval, manual and scheduled runs."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import app.main as m

client = TestClient(m.app)
KIM = {"Authorization": "Bearer dev:kim"}
LEE = {"Authorization": "Bearer dev:lee"}
ADMIN = {"Authorization": "Bearer dev:secops:tether-admins"}
ADMIN2 = {"Authorization": "Bearer dev:kim:tether-admins"}  # kim, as an administrator
ORCH = {"Authorization": "Bearer orchestrator-secret"}
JOB = {"name": "nightly-deps", "repo": "git@github.com:co/repo.git", "model": "company-coder-32b",
       "task": "Update dependencies and open a pull request.", "interval_minutes": 60, "max_runtime_seconds": 1800}


def request_job(headers=KIM, **kw):
    return client.post("/v1/agent/jobs", json={**JOB, **kw}, headers=headers)


def approved_job(**kw):
    j = request_job(**kw).json()
    r = client.post(f"/v1/admin/agent/jobs/{j['id']}/approve", json={"reason": "reviewed task"}, headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def run(job_id, trigger, user_token="dev:kim"):
    body = {"device_id": "mac-1", "agent": "local", "repo": "ignored", "job_id": job_id, "trigger": trigger}
    if trigger == "manual":
        body["user_token"] = user_token
    return client.post("/v1/agent/sessions", json=body, headers=ORCH)


def events(event_type):
    with m.Session() as db:
        return [e.payload for e in db.query(m.AuditEvent).filter_by(event_type=event_type).order_by(m.AuditEvent.id)]


def test_requested_jobs_wait_for_approval():
    r = request_job()
    assert r.status_code == 200 and r.json()["status"] == "pending" and r.json()["owner"] == "kim"
    e = events("agent.job.request")[-1]
    assert "task" not in e["unmapped"] and len(e["unmapped"]["task_sha256"]) == 64
    assert run(r.json()["id"], "manual").status_code == 403


@pytest.mark.parametrize("kw", [{"interval_minutes": 5}, {"max_runtime_seconds": 99999}, {"environment": "production"},
                                {"environment": "nowhere"}, {"task": ""}, {"repo": "not a repo"}])
def test_invalid_job_requests(kw):
    assert request_job(**kw).status_code == 422


def test_only_other_administrators_approve():
    j = request_job().json()
    assert client.post(f"/v1/admin/agent/jobs/{j['id']}/approve", json={"reason": "x"}, headers=LEE).status_code == 403
    assert client.post(f"/v1/admin/agent/jobs/{j['id']}/approve", json={"reason": "x"}, headers=ADMIN2).status_code == 403  # own job
    r = client.post(f"/v1/admin/agent/jobs/{j['id']}/approve", json={"reason": "ok"}, headers=ADMIN)
    assert r.json()["status"] == "approved" and r.json()["decided_by"] == "secops"
    assert events("agent.job.approve")[-1]["unmapped"]["job_id"] == j["id"]
    assert client.post(f"/v1/admin/agent/jobs/{j['id']}/approve", json={"reason": "again"}, headers=ADMIN).status_code == 409


def test_rejected_and_disabled_jobs_do_not_run():
    j = request_job().json()
    client.post(f"/v1/admin/agent/jobs/{j['id']}/reject", json={"reason": "too broad"}, headers=ADMIN)
    assert run(j["id"], "manual").status_code == 403
    a = approved_job()
    client.post(f"/v1/admin/agent/jobs/{a['id']}/disable", json={"reason": "owner left"}, headers=ADMIN)
    assert run(a["id"], "manual").status_code == 403 and run(a["id"], "schedule").status_code == 403


def test_listing():
    approved_job(); request_job(headers=LEE)
    assert {j["owner"] for j in client.get("/v1/agent/jobs", headers=KIM).json()["jobs"]} == {"kim"}
    assert {j["owner"] for j in client.get("/v1/agent/jobs", headers=ADMIN).json()["jobs"]} == {"kim", "lee"}
    assert [j["status"] for j in client.get("/v1/agent/jobs", headers=ADMIN, params={"status": "pending"}).json()["jobs"]] == ["pending"]


def test_manual_run_by_owner_or_admin_only():
    j = approved_job()
    assert run(j["id"], "manual", "dev:lee").status_code == 403
    r = run(j["id"], "manual")
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["user_id"] == "kim" and s["job"]["trigger"] == "manual" and s["job"]["task"] == JOB["task"]
    assert s["sandbox_name"].startswith(f"agent-job-{j['id'][:8]}")  # never the developer's own sandbox
    created = events("session.create")[-1]["unmapped"]
    assert created["job_id"] == j["id"] and created["triggered_by"] == "kim" and created["agent"] == "local"


def test_one_run_at_a_time_and_ending_frees_the_job():
    j = approved_job()
    s = run(j["id"], "manual").json()
    assert run(j["id"], "manual").status_code == 409
    assert client.post(f"/v1/agent/sessions/{s['session_id']}/end", headers=KIM).status_code == 403
    assert client.post(f"/v1/agent/sessions/{s['session_id']}/end", headers=ORCH).status_code == 200
    assert events("session.end")[-1]["unmapped"]["job_id"] == j["id"]
    assert run(j["id"], "manual", "dev:secops:tether-admins").status_code == 200


def test_job_session_lifetime_is_bounded_by_max_runtime():
    s = run(approved_job(max_runtime_seconds=600)["id"], "manual").json()
    with m.Session() as db:
        t = db.get(m.SessionToken, s["session_id"])
        assert m.utc(t.expires_at) <= m.now() + timedelta(seconds=600 + m.JOB_SESSION_GRACE_SECONDS)


def test_schedule_is_enforced_by_the_policy_api():
    j = approved_job(interval_minutes=60)
    assert [d["id"] for d in client.get("/v1/agent/jobs/due", headers=ORCH).json()["jobs"]] == [j["id"]]
    s = run(j["id"], "schedule")
    assert s.status_code == 200 and s.json()["user_id"] == f"job:{j['id']}" and s.json()["job"]["triggered_by"] == "schedule"
    client.post(f"/v1/agent/sessions/{s.json()['session_id']}/end", headers=ORCH)
    # Not due again for an hour, even if the orchestrator asks.
    assert client.get("/v1/agent/jobs/due", headers=ORCH).json()["jobs"] == []
    assert run(j["id"], "schedule").status_code == 409
    with m.Session() as db:
        db.get(m.AgentJob, j["id"]).last_scheduled_at = m.now() - timedelta(minutes=61)
        db.commit()
    assert run(j["id"], "schedule").status_code == 200


def test_unscheduled_jobs_never_run_on_schedule():
    j = approved_job(interval_minutes=None)
    assert run(j["id"], "schedule").status_code == 403
    assert client.get("/v1/agent/jobs/due", headers=ORCH).json()["jobs"] == []


def test_local_agent_needs_a_job_and_a_trigger():
    body = {"device_id": "mac-1", "agent": "local", "repo": "git@github.com:co/repo.git", "user_token": "dev:kim"}
    assert client.post("/v1/agent/sessions", json=body, headers=ORCH).status_code == 403
    j = approved_job()
    assert client.post("/v1/agent/sessions", json={**body, "job_id": j["id"]}, headers=ORCH).status_code == 422


def test_due_is_orchestrator_only():
    assert client.get("/v1/agent/jobs/due", headers=ADMIN).status_code == 403


def test_orchestrator_reads_job_sessions_but_not_developer_sessions():
    s = run(approved_job()["id"], "manual").json()
    assert client.get(f"/v1/agent/sessions/{s['session_id']}", headers=ORCH).status_code == 200
    dev = client.post("/v1/agent/sessions", json={"device_id": "mac-1", "agent": "claude", "repo": "git@github.com:co/repo.git",
                                                  "user_token": "dev:kim"}, headers=ORCH).json()
    assert client.get(f"/v1/agent/sessions/{dev['session_id']}", headers=ORCH).status_code == 404
    assert client.get(f"/v1/agent/sessions/{s['session_id']}", headers={"Authorization": f"Bearer {s['session_token']}"}).status_code == 403


def test_kill_switch_by_job():
    j = approved_job()
    s = run(j["id"], "manual").json()
    r = client.post("/v1/admin/sessions/revoke", json={"job_id": j["id"], "reason": "INC-77"}, headers=ADMIN)
    assert r.json()["revoked"] == 1 and r.json()["sessions"][0]["session_id"] == s["session_id"]
