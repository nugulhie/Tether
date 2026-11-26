#!/usr/bin/env python3
"""Staging end-to-end check of the sandbox lifecycle against the live OpenShell gateway.

Runs on the gateway host from the repository root after 30-control-plane.sh and 40-gateway-config.sh:
    python3 infra/staging/50-e2e.py
It drives the gateway with the orchestrator's own OpenShell wrapper (the same CLI calls the orchestrator
makes), but without GitHub: the github-org provider gets a placeholder credential and nothing is cloned.

Steps: issue a session (Policy API) -> providers -> create the sandbox from LOCAL_AGENT_IMAGE -> checks
inside it -> attempt to widen it -> kill switch (revoke, delete) -> re-creation refused.
Then one real job through the orchestrator (clones E2E_REPO from GitHub, runs the local model): request ->
approve -> run -> its owner reads the answer and patch; another person cannot.
Then Claude Code and Codex in a sandbox from SANDBOX_IMAGE (infra/sandbox-images/coding-agents): their prompts
reach the LLM gateway and are recorded; with ANTHROPIC_API_KEY / OPENAI_API_KEY set, the model answers.
Exit status is the number of failed checks. Stdlib only; reads tokens from infra/.env.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services/sandbox-orchestrator"))
from orchestrator.openshell import OpenShell, OpenShellError  # noqa: E402
from orchestrator.agents import agent_command  # noqa: E402

ENV = dict(line.split("=", 1) for line in (ROOT / "infra/.env").read_text().splitlines() if "=" in line and not line.startswith("#"))
POLICY_API = "http://127.0.0.1:8080"
ORCHESTRATOR = "http://172.30.0.1:8083"   # compose.staging.yml: the orchestrator listens on the compose network's gateway address
E2E_REPO = ENV.get("E2E_REPO", "https://github.com/nugulhie/Tether")   # public, in GITHUB_ORG
# The lifecycle checks use tether-agent and python3.13, which are in the local-agent image.
IMAGE = ENV.get("LOCAL_AGENT_IMAGE") or ENV["SANDBOX_IMAGE"]
AGENTS_IMAGE = ENV["SANDBOX_IMAGE"]
PLATFORM = "host.openshell.internal"   # PLATFORM_LLM_GATEWAY_HOST / PLATFORM_POLICY_API_HOST in compose.staging.yml
MODEL = ENV.get("STAGING_MODEL", "qwen3.5:122b")
gw = OpenShell()
failures = []
FETCH = """import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1], timeout=15)
    print("reached")
except urllib.error.HTTPError as e:
    print("reached", e.code)
except Exception as e:
    print("blocked", type(e).__name__, e)
"""


def person_token(user, groups=()):
    """A token as POST /v1/auth/token issues it (AUTH_MODE=mtls), signed with this host's USER_TOKEN_KEY.
    The certificate exchange itself is exercised from a person's machine (README)."""
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=")
    now = int(time.time())
    signing = b64({"alg": "HS256", "typ": "JWT"}) + b"." + b64({"iss": "tether-policy-api", "aud": "tether", "sub": user,
                                                               "groups": list(groups), "iat": now, "exp": now + 600})
    sig = base64.urlsafe_b64encode(hmac.new(ENV["USER_TOKEN_KEY"].encode(), signing, hashlib.sha256).digest()).rstrip(b"=")
    return (signing + b"." + sig).decode()


def check(name, ok, detail=""):
    print(f"[{'ok' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def api(method, path, token, body=None, base=POLICY_API, headers=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "content-type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


async def sh(name, script):
    return await gw.exec(name, ["sh", "-c", script])


async def refused(label, coro_factory, name):
    try:
        await coro_factory()
    except OpenShellError as e:
        check(label, True)
        return str(e)
    check(label, False, "gateway accepted it")
    if await gw.sandbox_exists(name):
        await gw.delete_sandboxes([name])


async def main():
    user = f"e2e-{secrets.token_hex(3)}"
    status, s = api("POST", "/v1/agent/sessions", ENV["ORCHESTRATOR_TOKEN"],
                    {"user_token": person_token(user), "device_id": "staging", "agent": "claude",
                     "repo": "https://github.com/your-org/demo", "environment": "development"})
    check("session issued", status == 200, s)
    if status != 200:
        return
    name, providers = s["sandbox_name"], list(s["providers"])
    print(f"     session {s['session_id']} sandbox {name} policy {s['policy_id']} v{s['policy_version']}")
    creds = {"tether-llm": {"ANTHROPIC_AUTH_TOKEN": s["session_token"], "TETHER_LLM_TOKEN": s["session_token"]},
             "tether-policy": {"TETHER_SESSION_TOKEN": s["session_token"]},
             "github-org": {"GITHUB_TOKEN": "staging-placeholder", "GH_TOKEN": "staging-placeholder"}}
    labels = {"managed-by": "tether-staging-e2e", "session": s["session_id"]}
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        json.dump(s["openshell_policy"], f)  # JSON is YAML
        policy_file = f.name
    try:
        for pname, profile in s["providers"].items():
            await gw.upsert_provider(pname, profile, creds[profile])
        check("issued providers created", True)

        await refused("create from an unapproved image refused",
                      lambda: gw.create_sandbox(name, "python:3.13-slim", policy_file, providers, labels), name)
        # Ask for fewer providers: the interceptor's modify phase replaces spec.providers with the issued set.
        await gw.create_sandbox(name, IMAGE, policy_file, providers[:1], labels)
        check("sandbox created from the issued session", await gw.sandbox_exists(name))
        _, out, _ = await gw.run("sandbox", "get", name, "-o", "json")
        annotations = json.loads(out).get("annotations") or {}
        check("interceptor stamped the issued session and policy", annotations.get("tether/session-id") == s["session_id"]
              and annotations.get("tether/policy-hash") == s["policy_hash"], annotations)
        _, out, _ = await gw.run("sandbox", "provider", "list", name)
        got = sorted(p for p in s["providers"] if p in out.split())
        check("providers replaced with exactly the issued set", got == sorted(providers), out)
        await refused("attaching an unissued provider refused", lambda: gw.run("sandbox", "provider", "attach", name, "rogue-llm"), "")

        rc, out, err = await sh(name, "id -u; pwd")
        check("runs as the image's unprivileged user in /workspace", rc == 0 and out.split() == ["10001", "/workspace"], out + err)
        rc, _, err = await sh(name, "echo x > /workspace/probe && cat /workspace/probe")
        check("workspace is writable", rc == 0, err)
        rc, _, _ = await sh(name, "echo x > /usr/probe")
        check("/usr is not writable", rc != 0)
        rc, _, _ = await sh(name, "ls /root")
        check("paths outside the policy are not readable (/root)", rc != 0)

        await gw.write_file(name, "/tmp/fetch.py", FETCH.encode())
        py = "/usr/local/bin/python3.13"
        for url, want, label in [("https://pypi.org/simple/pip/", "reached", "allowed host reachable by an allowed binary (python3.13 -> pypi.org)"),
                                 ("https://example.com/", "blocked", "host outside network.allow blocked (example.com)"),
                                 ("https://api.anthropic.com/v1/models", "blocked", "model provider not reachable directly (api.anthropic.com)")]:
            rc, out, err = await gw.exec(name, [py, "/tmp/fetch.py", url])
            check(label, out.startswith(want), (out + err).strip()[-300:])
        rc, out, err = await sh(name, f"cp {py} /tmp/py && /tmp/py /tmp/fetch.py https://pypi.org/simple/pip/")
        check("allowed host blocked for an unlisted binary (copied interpreter)", not out.startswith("reached"), (out + err).strip()[-300:])

        # The platform (host.openshell.internal) is for agent binaries only; host services other than :443 never.
        for url, label in [(f"https://{PLATFORM}/local/v1/models", "LLM gateway not reachable by a non-agent binary (python3.13)"),
                           (f"http://{PLATFORM}:11434/api/tags", "inference engine not reachable from the sandbox (host :11434)"),
                           ("https://192.168.1.27:8443/v1/models", "inference proxy not reachable from the sandbox (server IP :8443)")]:
            rc, out, err = await gw.exec(name, [py, "/tmp/fetch.py", url])
            check(label, out.startswith("blocked"), (out + err).strip()[-300:])

        # Model calls: tether-agent (an agent binary) through the TLS front and LLM gateway to the local model.
        agent_env = {"OPENAI_BASE_URL": f"https://{PLATFORM}/local/v1", "TETHER_MODEL": MODEL, "TETHER_TASK_FILE": "/tmp/task",
                     "TETHER_MAX_STEPS": "3", "TETHER_JOB": "staging-e2e"}
        await gw.write_file(name, "/tmp/task", b"Do not run any command. Immediately call the finish tool with the summary 'ok'.")
        rc, out, err = await gw.exec(name, ["/usr/local/bin/tether-agent"], "/workspace", env=agent_env)
        check("local model answers through the LLM gateway (tether-agent exit 0)", rc == 0, f"rc={rc} {(out + err).strip()[-600:]}")
        await gw.write_file(name, "/tmp/task", b"Store this deploy key for later: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        rc, out, err = await gw.exec(name, ["/usr/local/bin/tether-agent"], "/workspace", env=agent_env)
        check("guardrail blocks a secret in the prompt (exit 4)", rc == 4, f"rc={rc} {(out + err).strip()[-600:]}")
        agent_env["TETHER_MODEL"] = "bge-m3:latest"
        await gw.write_file(name, "/tmp/task", b"Call finish with the summary 'ok'.")
        rc, out, err = await gw.exec(name, ["/usr/local/bin/tether-agent"], "/workspace", env=agent_env)
        check("model outside the policy's llm.local.models refused (exit 4)", rc == 4, f"rc={rc} {(out + err).strip()[-600:]}")

        # Widening the policy of a live sandbox must be refused by the interceptor.
        wide = json.loads(json.dumps(s["openshell_policy"]))
        next(iter(wide["network_policies"].values()))["endpoints"].append({"host": "example.com", "port": 443})
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            json.dump(wide, f)
            wide_file = f.name
        try:
            await refused("widened live policy refused", lambda: gw.set_policy(name, wide_file), "")
        finally:
            Path(wide_file).unlink()

        # Kill switch: an administrator revokes the session; the orchestrator deletes the sandbox.
        status, r = api("POST", "/v1/admin/sessions/revoke", person_token("e2e-admin", ["tether-admins"]),
                        {"session_id": s["session_id"], "reason": "staging e2e"})
        check("session revoked by an administrator", status == 200 and r["revoked"] == 1, r)
        status, _ = api("GET", "/v1/admin/guardrails/bypass", "dev:e2e-admin:tether-admins")   # read-only probe
        check("dev tokens are refused (AUTH_MODE=mtls)", status == 401)
        await gw.delete_sandboxes([name])
        check("sandbox deleted", not await gw.sandbox_exists(name))
        await refused("re-creation after revoke refused", lambda: gw.create_sandbox(name, IMAGE, policy_file, providers, labels), name)
    finally:
        Path(policy_file).unlink()
        if await gw.sandbox_exists(name):
            await gw.delete_sandboxes([name])
        for pname in providers:
            await gw.run("provider", "delete", pname, check=False)


def job_checks():
    owner, admin = person_token(f"e2e-{secrets.token_hex(3)}"), person_token("e2e-admin", ["tether-admins"])
    status, j = api("POST", "/v1/agent/jobs", owner, {
        "name": "staging e2e", "repo": E2E_REPO, "model": MODEL, "max_runtime_seconds": 600,
        "task": "Create a file named E2E.txt in the repository root containing exactly the word tether. "
                "Then call finish with the summary: e2e done."})
    check("job requested (pending)", status == 200 and j["status"] == "pending", j)
    if status != 200:
        return
    try:
        status, _ = api("POST", f"/v1/admin/agent/jobs/{j['id']}/approve", admin, {"reason": "staging e2e"})
        check("job approved by an administrator", status == 200)
        # As tls-front forwards it: the person's token and the certificate serial header.
        status, run = api("POST", f"/v1/jobs/{j['id']}/run", owner, base=ORCHESTRATOR, headers={"x-tether-client-serial": "e2e"})
        check("job run started through the orchestrator", status == 200 and run.get("status") == "started", run)
        if status != 200:
            return
        deadline, r = time.monotonic() + 660, None
        while time.monotonic() < deadline:
            _, runs = api("GET", f"/v1/agent/jobs/{j['id']}/runs", owner)
            r = next((x for x in runs["runs"] if x["session_id"] == run["session_id"]), None)
            if r and r["status"] != "running":
                break
            time.sleep(5)
        check("job run finished with a stored result", bool(r) and r["status"] == "finished" and r.get("returncode") == 0, r)
        status, v = api("GET", f"/v1/agent/jobs/{j['id']}/runs/{run['session_id']}", owner)
        check("owner reads the answer with the changed-file list", status == 200 and "Changed files" in (v.get("output") or ""),
              (v.get("output") or "")[-300:])
        check("owner reads the patch with the agent's new file", status == 200 and "b/E2E.txt" in (v.get("diff") or ""),
              (v.get("diff") or "")[:300])
        status, _ = api("GET", f"/v1/agent/jobs/{j['id']}/runs/{run['session_id']}", person_token("e2e-someone-else"))
        check("another person cannot see the job's result (404)", status == 404)
    finally:
        api("POST", f"/v1/admin/agent/jobs/{j['id']}/disable", admin, {"reason": "staging e2e finished"})


async def coding_agent_checks():
    """Claude Code and Codex as the orchestrator runs them (same argv and environment), non-interactively."""
    admin = person_token("e2e-admin", ["tether-admins"])
    for agent, prompt_args, key in [("claude", ["-p", "Reply with exactly: TETHER-OK"], "ANTHROPIC_API_KEY"),
                                    ("codex", ["exec", "--skip-git-repo-check", "Reply with exactly: TETHER-OK"], "OPENAI_API_KEY")]:
        status, s = api("POST", "/v1/agent/sessions", ENV["ORCHESTRATOR_TOKEN"],
                        {"user_token": person_token(f"e2e-{secrets.token_hex(3)}"), "device_id": "staging", "agent": agent,
                         "repo": "https://github.com/your-org/demo", "environment": "development"})
        check(f"{agent}: session issued", status == 200, s)
        if status != 200:
            continue
        name, providers = s["sandbox_name"], list(s["providers"])
        creds = {"tether-llm": {"ANTHROPIC_AUTH_TOKEN": s["session_token"], "TETHER_LLM_TOKEN": s["session_token"]},
                 "tether-policy": {"TETHER_SESSION_TOKEN": s["session_token"]},
                 "github-org": {"GITHUB_TOKEN": "staging-placeholder", "GH_TOKEN": "staging-placeholder"}}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            json.dump(s["openshell_policy"], f)
            policy_file = f.name
        try:
            for pname, profile in s["providers"].items():
                await gw.upsert_provider(pname, profile, creds[profile])
            await gw.create_sandbox(name, AGENTS_IMAGE, policy_file, providers, {"managed-by": "tether-staging-e2e", "session": s["session_id"]})
            argv, agent_env = agent_command(agent, f"https://{PLATFORM}")
            rc, out, err = await gw.exec(name, [*argv, *prompt_args], "/workspace", env=agent_env)
            tail = (out + err).strip()[-400:]
            status, c = api("GET", f"/v1/audit/content?session_id={s['session_id']}", admin)
            recorded = status == 200 and any(x["direction"] == "request" for x in c["contents"])
            if ENV.get(key):
                check(f"{agent}: prompt reached the LLM gateway and was recorded", recorded, f"rc={rc} {tail}")
            else:  # no company key: the gateway answers that the provider is not configured, before storing anything
                check(f"{agent}: reaches the LLM gateway (provider not configured there)", "not configured on this gateway" in out + err, f"rc={rc} {tail}")
            if ENV.get(key):
                check(f"{agent}: external model answers through the gateway", rc == 0 and "TETHER-OK" in out, f"rc={rc} {tail}")
            else:
                print(f"     ({agent}: {key} is not set on the gateway, so the model call itself is not checked)")
        finally:
            Path(policy_file).unlink()
            api("POST", "/v1/admin/sessions/revoke", admin, {"session_id": s["session_id"], "reason": "staging e2e"})
            if await gw.sandbox_exists(name):
                await gw.delete_sandboxes([name])
            for pname in providers:
                await gw.run("provider", "delete", pname, check=False)


asyncio.run(main())
job_checks()
asyncio.run(coding_agent_checks())
print(f"\n{len(failures)} failed" + (": " + ", ".join(failures) if failures else ""))
sys.exit(len(failures))
