#!/usr/bin/env python3
"""Staging end-to-end check of the sandbox lifecycle against the live OpenShell gateway.

Runs on the gateway host from the repository root after 30-control-plane.sh and 40-gateway-config.sh:
    python3 infra/staging/50-e2e.py
It drives the gateway with the orchestrator's own OpenShell wrapper (the same CLI calls the orchestrator
makes), but without GitHub: the github-org provider gets a placeholder credential and nothing is cloned.

Steps: issue a session (Policy API) -> providers -> create the sandbox from SANDBOX_IMAGE -> checks
inside it -> attempt to widen it -> kill switch (revoke, delete) -> re-creation refused.
Exit status is the number of failed checks. Stdlib only; reads tokens from infra/.env.
"""
import asyncio
import json
import secrets
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services/sandbox-orchestrator"))
from orchestrator.openshell import OpenShell, OpenShellError  # noqa: E402

ENV = dict(line.split("=", 1) for line in (ROOT / "infra/.env").read_text().splitlines() if "=" in line and not line.startswith("#"))
POLICY_API = "http://127.0.0.1:8080"
IMAGE = ENV["SANDBOX_IMAGE"]
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


def check(name, ok, detail=""):
    print(f"[{'ok' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def api(method, path, token, body=None):
    req = urllib.request.Request(POLICY_API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "content-type": "application/json"})
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
                    {"user_token": f"dev:{user}", "device_id": "staging", "agent": "claude",
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
        status, r = api("POST", "/v1/admin/sessions/revoke", "dev:sec-admin:tether-admins",
                        {"session_id": s["session_id"], "reason": "staging e2e"})
        check("session revoked by an administrator", status == 200 and r["revoked"] == 1, r)
        await gw.delete_sandboxes([name])
        check("sandbox deleted", not await gw.sandbox_exists(name))
        await refused("re-creation after revoke refused", lambda: gw.create_sandbox(name, IMAGE, policy_file, providers, labels), name)
    finally:
        Path(policy_file).unlink()
        if await gw.sandbox_exists(name):
            await gw.delete_sandboxes([name])
        for pname in providers:
            await gw.run("provider", "delete", pname, check=False)


asyncio.run(main())
print(f"\n{len(failures)} failed" + (": " + ", ".join(failures) if failures else ""))
sys.exit(len(failures))
