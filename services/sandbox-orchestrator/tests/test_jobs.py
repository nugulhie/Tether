"""Local-LLM agent jobs (ADR 0001, D1): manual and scheduled runs, bounded and torn down."""
import asyncio
import json
import time

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import orchestrator.main as o
from test_orchestrator import BASE_SESSION, World

ORCH = "Bearer orch-secret"
JOB = {"id": "job-1", "name": "nightly-deps", "owner": "kim", "repo": "git@github.com:acme/payments.git", "model": "company-coder-32b",
       "task": "Update dependencies and open a pull request.", "max_runtime_seconds": 30}


class JobWorld(World):
    def __init__(self, monkeypatch, tmp_path, trigger="manual", user="kim", repo=None):
        job = {**JOB, "repo": repo or JOB["repo"], "trigger": trigger, "triggered_by": user if trigger == "manual" else "schedule"}
        super().__init__(monkeypatch, tmp_path, session={**BASE_SESSION, "user_id": user if trigger == "manual" else "job:job-1",
                                                         "sandbox_name": "agent-job-job-1-abc-def", "job": job,
                                                         "providers": {"agent-job-job-1-abc-def-llm": "tether-llm",
                                                                       "agent-job-job-1-abc-def-github": "github-org"}})
        self.ended, self.due, self.credential_auth = [], [{"id": "job-1", "name": "nightly-deps"}], []
        monkeypatch.setenv("POLICY_API_PUBLIC_URL", "https://policy.company.internal")

    def handle(self, req):
        p = req.url.path
        if p.endswith("/end"):
            assert req.headers["authorization"] == ORCH
            self.ended.append(p.split("/")[-2])
            return httpx.Response(200, json={"ended": p.split("/")[-2]})
        if p == "/v1/agent/jobs/due":
            assert req.headers["authorization"] == ORCH
            return httpx.Response(200, json={"jobs": self.due})
        if p.startswith("/v1/credentials/"):
            self.credential_auth.append(req.headers["authorization"])
            return httpx.Response(200, json={"token": "ghs_SECRET", "expires_at": "x"})
        return super().handle(req)

    def execs(self):
        return [c for c in self.calls() if c["argv"][:2] == ["sandbox", "exec"]]

    def task_writes(self):
        return [c for c in self.execs() if c["argv"][c["argv"].index("--") + 1:][:2] == ["sh", "-c"]]

    def agent_runs(self):
        return [c["argv"] for c in self.execs() if "clone" not in c["argv"] and c not in self.task_writes()]


def start(trigger="manual", token="dev:kim"):
    async def go():
        r = await o.start_job("job-1", trigger, token)
        await o.state.runs[r["session_id"]]
        return r
    return asyncio.run(go())


def test_manual_run_executes_the_approved_task_and_tears_down(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    r = start()
    assert r["status"] == "started" and r["sandbox_name"] == "agent-job-job-1-abc-def"
    assert w.session_request == {"user_token": "dev:kim", "device_id": "scheduler", "device_verified": False, "agent": "local", "repo": "-",
                                 "job_id": "job-1", "trigger": "manual"}
    # Credentials for job sessions are requested with the orchestrator's identity (no person behind schedules).
    assert w.credential_auth == [ORCH]
    run = w.agent_runs()[-1]
    assert "--no-tty" in run and run[-1] == "tether-agent"
    envs = dict(run[i + 1].split("=", 1) for i, a in enumerate(run) if a == "--env")
    assert envs["OPENAI_BASE_URL"] == "https://llm.company.internal/local/v1"
    assert envs["TETHER_MODEL"] == "company-coder-32b" and envs["TETHER_JOB"] == "job-1"
    # The task reaches the sandbox through stdin into a file; only the file's path is in argv.
    assert envs["TETHER_TASK_FILE"] == o.TASK_FILE and "TETHER_TASK" not in envs
    [write] = w.task_writes()
    assert write["stdin"] == JOB["task"] and write["argv"][-1] == o.TASK_FILE and "--env" not in write["argv"]
    execs = [c["argv"] for c in w.execs()]
    assert execs.index(write["argv"]) < execs.index(run)
    all_argv = json.dumps([c["argv"] for c in w.calls()])
    assert JOB["task"] not in all_argv and "Update dependencies" not in all_argv
    assert "ghs_SECRET" not in all_argv and "ast_SECRET" not in all_argv
    assert ["sandbox", "delete", "agent-job-job-1-abc-def"] in [c["argv"] for c in w.calls()]
    assert w.ended == ["sid-1"] and o.state.runs == {}
    exit_event = next(a for a in w.audits if a["event_type"] == "agent.exit")
    assert exit_event["data"]["returncode"] == 0 and exit_event["data"]["job_id"] == "job-1" and exit_event["data"]["trigger"] == "manual"
    assert [a["event_type"] for a in w.audits] == ["sandbox.create", "agent.exit", "sandbox.delete"]


def test_runtime_limit_stops_the_run(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    monkeypatch.setenv("FAKE_AGENT_SLEEP", "5")
    w.session["job"]["max_runtime_seconds"] = 0.5
    t0 = time.monotonic()
    start()
    assert time.monotonic() - t0 < 4
    exit_event = next(a for a in w.audits if a["event_type"] == "agent.exit")
    assert exit_event["data"]["timed_out"] is True and exit_event["success"] is False
    assert w.ended == ["sid-1"] and any(c["argv"][:2] == ["sandbox", "delete"] for c in w.calls())


def test_failed_run_is_recorded(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    monkeypatch.setenv("FAKE_AGENT_RC", "7")
    start()
    exit_event = next(a for a in w.audits if a["event_type"] == "agent.exit")
    assert exit_event["data"]["returncode"] == 7 and exit_event["success"] is False


def test_task_delivery_failure_fails_the_run_without_starting_the_agent(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    monkeypatch.setenv("FAKE_WRITE_RC", "1")
    start()
    exit_event = next(a for a in w.audits if a["event_type"] == "agent.exit")
    assert exit_event["success"] is False and exit_event["data"]["returncode"] is None and "writing" in exit_event["data"]["error"]
    assert w.agent_runs() == [] and w.ended == ["sid-1"] and any(c["argv"][:2] == ["sandbox", "delete"] for c in w.calls())


def test_job_repo_outside_org_ends_the_session(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path, repo="git@github.com:evil/payments.git")
    with pytest.raises(HTTPException) as e:
        start()
    assert e.value.status_code == 403 and w.ended == ["sid-1"] and w.agent_runs() == []


def test_policy_api_refusal_passes_through(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    w.policy_status = 403
    with pytest.raises(HTTPException) as e:
        start()
    assert e.value.status_code == 403 and w.calls() == []


def test_scheduled_runs_use_what_the_policy_api_says_is_due(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path, trigger="schedule")

    async def go():
        started = await o.run_due_jobs()
        await asyncio.gather(*o.state.runs.values())
        return started
    started = asyncio.run(go())
    assert [s["trigger"] for s in started] == ["schedule"]
    assert w.session_request["trigger"] == "schedule" and w.session_request["user_token"] == ""
    w.due = []
    assert asyncio.run(o.run_due_jobs()) == []


def test_scheduler_skips_jobs_the_policy_api_refuses(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path, trigger="schedule")
    w.policy_status = 409  # still running / not due
    assert asyncio.run(o.run_due_jobs()) == [] and w.calls() == []


def test_run_endpoint_needs_a_person(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    with TestClient(o.app) as c:
        assert c.post("/v1/jobs/job-1/run").status_code == 401
        r = c.post("/v1/jobs/job-1/run", headers={"Authorization": "Bearer dev:kim"})
        assert r.status_code == 200 and "ast_SECRET" not in r.text
        deadline = time.monotonic() + 5
        while o.state.runs and time.monotonic() < deadline:
            time.sleep(0.05)
    assert w.session_request["user_token"] == "dev:kim" and w.ended == ["sid-1"]


def test_kill_switch_accepts_job_selector(monkeypatch, tmp_path):
    w = JobWorld(monkeypatch, tmp_path)
    r = TestClient(o.app).post("/v1/admin/revoke", headers={"Authorization": "Bearer dev:secops"}, json={"job_id": "job-1", "reason": "INC-77"})
    assert r.status_code == 200
    revoke = next(json.loads(q.content) for q in w.requests if q.url.path == "/v1/admin/sessions/revoke")
    assert revoke["job_id"] == "job-1"
