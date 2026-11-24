import json
from pathlib import Path

import httpx
import pytest

from tether_agent import agent
from tether_agent.tools import Tools

TASK = "Bump the version in VERSION to 2 and run the tests."


def call(name, call_id="c1", **args):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def reply(*calls, content=None):
    msg = {"role": "assistant", "content": content}
    if calls:
        msg["tool_calls"] = list(calls)
    return httpx.Response(200, json={"choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if calls else "stop"}]})


class FakeModel:
    """Answers chat/completions from a script; each entry is a Response or a callable(request_body) -> Response."""

    def __init__(self, *script):
        self.script, self.requests = list(script), []

    def __call__(self, request: httpx.Request):
        body = json.loads(request.content)
        self.requests.append((request, body))
        nxt = self.script.pop(0)
        return nxt(body) if callable(nxt) else nxt

    def tool_results(self, i):
        return [m for m in self.requests[i][1]["messages"] if m["role"] == "tool"]


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    (d / "VERSION").write_text("1\n")
    (tmp_path / "secret.txt").write_text("outside")
    return d


def env(tmp_path, **extra):
    task = tmp_path / "task.txt"
    task.write_text(TASK)
    return {"OPENAI_BASE_URL": "https://llm.company.internal/local/v1/", "TETHER_MODEL": "company-coder-32b",
            "TETHER_LLM_TOKEN": "openshell:resolve:env:TETHER_LLM_TOKEN", "TETHER_TASK_FILE": str(task),
            "TETHER_JOB": "job-1", **extra}


def run(model, environ, repo, sleeps=None):
    return agent.main(environ, transport=httpx.MockTransport(model), sleep=(sleeps.append if sleeps is not None else lambda s: None),
                      workdir=str(repo))


def logs(capsys):
    return [json.loads(l) for l in capsys.readouterr().err.splitlines() if l.startswith("{")]


def test_happy_path_reaches_finish(tmp_path, repo, capsys):
    model = FakeModel(
        reply(call("list_dir", "a", path="."), call("read_file", "b", path="VERSION")),
        reply(call("write_file", "c", path="VERSION", content="2\n"), call("run_shell", "d", command="cat VERSION && echo ok")),
        reply(call("finish", "e", summary="bumped to 2")),
    )
    assert run(model, env(tmp_path), repo) == 0
    assert (repo / "VERSION").read_text() == "2\n"
    req, body = model.requests[0]
    assert str(req.url) == "https://llm.company.internal/local/v1/chat/completions"
    # The placeholder is sent as-is; OpenShell swaps in the session token for the gateway host only.
    assert req.headers["authorization"] == "Bearer openshell:resolve:env:TETHER_LLM_TOKEN"
    assert body["model"] == "company-coder-32b" and body["messages"][1] == {"role": "user", "content": TASK}
    assert {t["function"]["name"] for t in body["tools"]} == {"read_file", "write_file", "list_dir", "run_shell", "finish"}
    first = model.tool_results(1)
    assert first[0]["tool_call_id"] == "a" and "VERSION" in first[0]["content"] and first[1]["content"] == "1\n"
    shell = model.tool_results(2)[-1]["content"]
    assert shell.startswith("exit code 0") and "2\nok" in shell
    out = capsys.readouterr()
    assert out.out.strip() == "bumped to 2"
    events = [json.loads(l) for l in out.err.splitlines()]
    assert [e["event"] for e in events] == ["start", "step", "tool", "tool", "step", "tool", "tool", "step", "finish"]
    assert TASK not in out.err and "bumped" not in out.err  # tool names and sizes only


def test_task_env_fallback(tmp_path, repo):
    environ = env(tmp_path)
    del environ["TETHER_TASK_FILE"]
    model = FakeModel(reply(call("finish", summary="done")))
    assert run(model, {**environ, "TETHER_TASK": "from env"}, repo) == 0
    assert model.requests[0][1]["messages"][1]["content"] == "from env"


@pytest.mark.parametrize("environ_patch", [{"TETHER_LLM_TOKEN": ""}, {"TETHER_MODEL": ""}, {"TETHER_TASK_FILE": "/nonexistent"},
                                           {"TETHER_MAX_STEPS": "0"}, {"TETHER_MAX_STEPS": "lots"}])
def test_bad_configuration_exits_before_any_request(tmp_path, repo, environ_patch):
    model = FakeModel()
    assert run(model, {**env(tmp_path), **environ_patch}, repo) == agent.EXIT_CONFIG
    assert model.requests == []


@pytest.mark.parametrize("args", [{"path": "../secret.txt"}, {"path": "/etc/passwd"}, {"path": "sub/../../secret.txt"}])
def test_path_escape_is_rejected(tmp_path, repo, args):
    model = FakeModel(reply(call("read_file", **args)), reply(call("write_file", path="../evil.txt", content="x")),
                      reply(call("finish", summary="gave up")))
    assert run(model, env(tmp_path), repo) == 0
    assert model.tool_results(1)[-1]["content"].startswith("error: path is outside the repository")
    assert model.tool_results(2)[-1]["content"].startswith("error: path is outside the repository")
    assert not (tmp_path / "evil.txt").exists()


def test_symlink_escape_is_rejected(tmp_path, repo):
    (repo / "link").symlink_to(tmp_path)
    tools = Tools(str(repo), 4096, 5)
    for fn in (lambda: tools.call("read_file", '{"path": "link/secret.txt"}'), lambda: tools.call("write_file", '{"path": "link/x", "content": "x"}'),
               lambda: tools.call("list_dir", '{"path": "link"}')):
        with pytest.raises(Exception, match="outside the repository"):
            fn()


def test_shell_timeout_kills_the_command(tmp_path, repo):
    model = FakeModel(reply(call("run_shell", command="sleep 30; echo never")), reply(call("finish", summary="ok")))
    assert run(model, env(tmp_path, TETHER_SHELL_TIMEOUT="1"), repo) == 0
    out = model.tool_results(1)[-1]["content"]
    assert out.startswith("timed out after 1s") and "never" not in out


def test_shell_output_is_truncated_and_runs_in_workdir_without_llm_token(tmp_path, repo):
    model = FakeModel(reply(call("run_shell", command="pwd; echo token=${TETHER_LLM_TOKEN:-none}; head -c 5000 /dev/zero | tr '\\0' x")),
                      reply(call("finish", summary="ok")))
    assert run(model, env(tmp_path, TETHER_MAX_OUTPUT_BYTES="1024"), repo) == 0
    out = model.tool_results(1)[-1]["content"]
    assert str(repo.resolve()) in out and "token=none" in out
    assert "[... truncated:" in out and len(out.encode()) < 1200


def test_403_exits_without_retry(tmp_path, repo, capsys):
    blocked = httpx.Response(403, json={"error": {"type": "permission_error", "message": "request blocked by guardrail: secrets"}})
    model = FakeModel(blocked, blocked)
    sleeps = []
    assert run(model, env(tmp_path), repo, sleeps) == agent.EXIT_REFUSED
    assert len(model.requests) == 1 and sleeps == []
    assert "blocked by guardrail: secrets" in capsys.readouterr().err


def test_403_after_tool_use_still_fails(tmp_path, repo):
    blocked = httpx.Response(403, json={"error": {"type": "permission_error", "message": "request blocked by guardrail: pii"}})
    model = FakeModel(reply(call("list_dir")), blocked)
    assert run(model, env(tmp_path), repo) == agent.EXIT_REFUSED


@pytest.mark.parametrize("body", [{"error": {"type": "api_error", "message": "guardrail unavailable; request refused"}},
                                  {"type": "error", "error": {"type": "api_error", "message": "audit store unavailable; request refused"}}])
def test_503_exits_unavailable_without_retry(tmp_path, repo, capsys, body):
    model = FakeModel(httpx.Response(503, json=body))
    assert run(model, env(tmp_path), repo) == agent.EXIT_UNAVAILABLE
    assert len(model.requests) == 1 and "unavailable; request refused" in capsys.readouterr().err


def test_transient_errors_are_retried(tmp_path, repo):
    model = FakeModel(httpx.Response(429, headers={"retry-after": "2"}), httpx.Response(502), reply(call("finish", summary="ok")))
    sleeps = []
    assert run(model, env(tmp_path), repo, sleeps) == 0
    assert sleeps == [2.0, 2] and len(model.requests) == 3


def test_step_limit(tmp_path, repo, capsys):
    model = FakeModel(*[reply(call("list_dir")) for _ in range(3)])
    assert run(model, env(tmp_path, TETHER_MAX_STEPS="3"), repo) == agent.EXIT_STEPS
    assert len(model.requests) == 3 and "step limit reached (3)" in capsys.readouterr().err


def test_text_only_replies_do_not_finish(tmp_path, repo):
    model = FakeModel(reply(content="All done!"), reply(content="Really done."))
    assert run(model, env(tmp_path, TETHER_MAX_STEPS="2"), repo) == agent.EXIT_STEPS


def test_bad_tool_calls_are_reported_to_the_model(tmp_path, repo):
    bad_json = {"id": "x", "type": "function", "function": {"name": "read_file", "arguments": "{not json"}}
    model = FakeModel(reply(bad_json, call("nope", "y"), call("read_file", "z", wrong=1), call("finish", "w", summary=5)),
                      reply(call("finish", summary="ok")))
    assert run(model, env(tmp_path), repo) == 0
    results = [m["content"] for m in model.tool_results(1)]
    assert results[0].startswith("error: arguments are not valid JSON") and "unknown tool" in results[1]
    assert "bad arguments" in results[2] and "summary" in results[3]


def test_malformed_gateway_response(tmp_path, repo):
    model = FakeModel(httpx.Response(200, json={"choices": []}))
    assert run(model, env(tmp_path), repo) == agent.EXIT_ERROR


def test_answer_ends_with_the_changed_files_from_git(tmp_path, repo, capsys):
    import subprocess
    git = lambda *a: subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=repo, check=True, capture_output=True)
    git("init", "-q"); git("add", "."); git("commit", "-qm", "init")
    model = FakeModel(reply(call("write_file", "a", path="VERSION", content="2\n"), call("write_file", "b", path="docs/요약.md", content="x")),
                      reply(call("finish", "c", summary="요약 내용 전체")))
    assert run(model, env(tmp_path), repo) == 0
    out = capsys.readouterr().out
    assert out.startswith("요약 내용 전체\n") and "Changed files" in out
    assert " M VERSION" in out and "?? docs/요약.md" in out  # new files too, names unescaped


def test_prompt_asks_for_the_answer_itself():
    p = agent.SYSTEM_PROMPT
    assert "only thing the person" in p and "is not an answer" in p and "language the task is written in" in p
