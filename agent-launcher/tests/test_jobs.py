"""tether job: request, approve, run and read results through the APIs."""
import json

import httpx
import pytest
from click.testing import CliRunner

import tether_launcher.cli as cli

JID = "0f3c2a9e-1111-4222-8333-444455556666"
JOB = {"id": JID, "name": "summarize", "owner": "kim", "status": "approved", "repo": "git@github.com:acme/payments.git",
       "model": "qwen3.5:122b", "task": "Summarize the README.", "interval_minutes": None, "max_runtime_seconds": 3600,
       "decided_by": "lee", "decision_reason": "ok"}
FINISHED = {"session_id": "sid-1", "status": "finished", "trigger": "manual", "started_at": "2026-11-24T10:00:00+00:00",
            "returncode": 0, "timed_out": False, "error": None, "output_truncated": False, "diff_truncated": False}
RESULT = {**FINISHED, "output": "It is a security platform.\n", "log": "{}\n", "diff": "diff --git a/x b/x\n", "purged": False}


class Api:
    def __init__(self, monkeypatch, tmp_path):
        self.requests, self.runs, self.polls = [], [FINISHED], 0
        monkeypatch.setattr(cli, "HOME", tmp_path)
        monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "token.json")
        monkeypatch.setattr(cli, "MANAGED_CONFIG", tmp_path / "none.json")
        monkeypatch.setattr(cli, "POLL_SECONDS", 0)
        monkeypatch.setenv("TETHER_TOKEN", "dev:kim")
        monkeypatch.setenv("TETHER_ORCHESTRATOR", "https://192.168.1.27")
        monkeypatch.setattr(cli, "http", lambda timeout=10: httpx.Client(transport=httpx.MockTransport(self.handle)))
        monkeypatch.setattr(cli.subprocess, "check_output", lambda *a, **k: "/src/repo\n")
        monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "git@github.com:acme/payments.git\n"})())

    def handle(self, req):
        self.requests.append(req)
        p, m = req.url.path, req.method
        assert req.headers["authorization"] == "Bearer dev:kim"
        if m == "POST" and p == "/v1/agent/jobs":
            return httpx.Response(200, json={**JOB, **json.loads(req.content), "status": "pending", "id": JID})
        if m == "GET" and p == "/v1/agent/jobs":
            return httpx.Response(200, json={"jobs": [JOB, {**JOB, "id": "99999999-0000-0000-0000-000000000000", "name": "other"}]})
        if p.startswith("/v1/admin/agent/jobs/"):
            return httpx.Response(200, json={**JOB, "status": {"approve": "approved", "reject": "rejected", "disable": "disabled"}[p.rsplit("/", 1)[1]]})
        if p == f"/v1/jobs/{JID}/run":
            return httpx.Response(200, json={"job_id": JID, "session_id": "sid-2", "sandbox_name": "j-abc", "status": "started"})
        if p == f"/v1/agent/jobs/{JID}/runs":
            self.polls += 1
            return httpx.Response(200, json={"runs": self.runs_now()})
        if p.startswith(f"/v1/agent/jobs/{JID}/runs/"):
            sid = p.rsplit("/", 1)[1]
            return httpx.Response(200, json={**RESULT, "session_id": sid})
        return httpx.Response(404, json={"detail": "not found"})

    def runs_now(self):
        return self.runs

    def body(self, path):
        return json.loads(next(r.content for r in self.requests if r.url.path == path))


def invoke(*args, input=None):
    return CliRunner().invoke(cli.cli, list(args), input=input)


def test_request_uses_this_checkout_and_the_default_model(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    monkeypatch.setenv("TETHER_MODEL", "qwen3.5:122b")
    r = invoke("job", "request", "--task", "Summarize the README.\nKeep it short.")
    assert r.exit_code == 0, r.output
    b = a.body("/v1/agent/jobs")
    assert b == {"name": "Summarize the README.", "repo": "git@github.com:acme/payments.git", "model": "qwen3.5:122b",
                 "task": "Summarize the README.\nKeep it short.", "interval_minutes": None, "max_runtime_seconds": 3600}
    assert f"{JID}  pending" in r.output and "approval" in r.output


def test_request_from_stdin_with_schedule(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    r = invoke("job", "request", "--task-file", "-", "--model", "m", "--every", "60", "--name", "nightly", input="Check deps")
    assert r.exit_code == 0, r.output
    assert a.body("/v1/agent/jobs")["task"] == "Check deps" and a.body("/v1/agent/jobs")["interval_minutes"] == 60


@pytest.mark.parametrize("args", [["--model", "m"], ["--model", "m", "--task", "x", "--task-file", "-"], ["--task", "x"]])
def test_request_needs_one_task_and_a_model(monkeypatch, tmp_path, args):
    Api(monkeypatch, tmp_path)
    r = invoke("job", "request", *args)
    assert r.exit_code != 0 and ("--task" in r.output or "--model" in r.output)


def test_jobs_are_named_by_unique_prefix(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    r = invoke("job", "approve", "0f3c", "--reason", "reviewed")
    assert r.exit_code == 0 and "approved" in r.output
    assert a.body(f"/v1/admin/agent/jobs/{JID}/approve") == {"reason": "reviewed"}
    assert "no job matches" in invoke("job", "reject", "abcd", "--reason", "x").output
    assert invoke("job", "disable", "0f3c").exit_code != 0  # a reason is required


def test_run_waits_and_prints_the_answer(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    states = iter([[], [{**FINISHED, "session_id": "sid-2", "status": "running"}], [{**FINISHED, "session_id": "sid-2"}]])
    a.runs_now = lambda: next(states)
    r = invoke("job", "run", "0f3c")
    assert r.exit_code == 0, r.output
    assert "It is a security platform." in r.output and a.polls >= 3
    run_req = next(q for q in a.requests if q.url.path == f"/v1/jobs/{JID}/run")
    assert run_req.method == "POST" and run_req.url.host == "192.168.1.27"


def test_run_without_waiting(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    r = invoke("job", "run", JID, "--no-wait")
    assert r.exit_code == 0 and "sid-2" in r.output and a.polls == 0


def test_result_prints_the_latest_answer_or_the_patch(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    a.runs = [{**FINISHED, "session_id": "sid-9", "status": "running"}, FINISHED]
    r = invoke("job", "result", "0f3c")
    assert r.exit_code == 0 and "It is a security platform." in r.output
    assert a.requests[-1].url.path.endswith("/runs/sid-1")  # latest finished, not the running one
    r = invoke("job", "result", "0f3c", "--diff")
    assert "diff --git a/x b/x" in r.output and "security platform" not in r.output


def test_failed_run_exits_non_zero(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    monkeypatch.setitem(RESULT, "returncode", 3)
    r = invoke("job", "result", JID)
    assert r.exit_code == 1 and "failed (exit 3)" in r.output


def test_refusals_are_clean_errors(monkeypatch, tmp_path):
    a = Api(monkeypatch, tmp_path)
    a.handle = lambda req: httpx.Response(403, json={"detail": "job is pending, not approved"})
    r = invoke("job", "run", JID)
    assert r.exit_code == 1 and "job is pending, not approved" in r.output and "Traceback" not in r.output


def test_show_lists_task_and_runs(monkeypatch, tmp_path):
    Api(monkeypatch, tmp_path)
    r = invoke("job", "show", "0f3c")
    assert r.exit_code == 0 and "Summarize the README." in r.output and "sid-1" in r.output and "ok" in r.output
