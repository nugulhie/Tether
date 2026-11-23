"""Sandbox orchestrator: the only path from a developer to an agent.

Developers authenticate with their OIDC token (and, behind the mTLS proxy, their device
certificate) and get a terminal. Everything else happens here, with credentials developers
never see:
  - session creation at the Policy API (the session token comes back to the orchestrator only),
  - short-lived AWS/GitHub credentials from the broker,
  - OpenShell providers (credentials bound to their destinations), sandbox creation on the
    managed gateway, live network policy updates, and cloning the repository inside the sandbox,
  - the terminal relay, and teardown for the incident-response kill switch.

Local-LLM agents (ADR 0001, D1) run only as administrator-approved jobs, non-interactively, in
a sandbox of their own: started by a person (`POST /v1/jobs/{id}/run`) or by the schedule
(`JOB_SCHEDULER=1`; the Policy API decides what is due). Each run is bounded by the job's
max runtime; afterwards its sandbox is deleted and its session ended.
"""
import asyncio
import json
import os
import re
import secrets
import tempfile
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request, WebSocket
from pydantic import BaseModel, Field

from .openshell import OpenShell, OpenShellError
from .relay import Relay

log = logging.getLogger("orchestrator")


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(scheduler()) if env("JOB_SCHEDULER") == "1" else None
    yield
    if task:
        task.cancel()


app = FastAPI(title="Company Agent Sandbox Orchestrator", lifespan=lifespan)
openshell = OpenShell(os.environ.get("OPENSHELL_BIN", "openshell"))
http_transport = None  # overridable in tests
TICKET_SECONDS = 60
AGENTS = {"claude": ["claude"], "codex": ["codex"]}


def env(name, default=""):
    return os.environ.get(name, default)


@dataclass
class Ticket:
    user_id: str
    session_id: str
    device_id: str
    sandbox: str
    agent: str
    workdir: str
    expires: float


@dataclass
class State:
    tickets: dict[str, Ticket] = field(default_factory=dict)
    relays: dict[str, Relay] = field(default_factory=dict)  # session_id -> live relay
    runs: dict[str, asyncio.Task] = field(default_factory=dict)  # session_id -> local-agent job run


state = State()


def http():
    return httpx.AsyncClient(timeout=30, transport=http_transport)


def bearer(request) -> str:
    h = request.headers.get("authorization", "")
    if not h.lower().startswith("bearer ") or not h[7:].strip():
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    return h[7:].strip()


def service_headers():
    return {"Authorization": f"Bearer {env('ORCHESTRATOR_TOKEN')}"}


async def call(method, url, *, headers, json_body=None, ok=(200,)):
    async with http() as c:
        r = await c.request(method, url, headers=headers, json=json_body)
    if r.status_code not in ok:
        detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
        # Pass client-facing verdicts (auth, policy, expiry) through; anything else is ours.
        raise HTTPException(r.status_code if r.status_code in (401, 403, 404, 409, 410, 422) else 502, detail)
    return r.json()


async def audit(event_type, s, data, success=True):
    body = {"event_type": event_type, "session_id": s["session_id"], "user_id": s["user_id"], "device_id": s.get("device_id"),
            "success": success, "data": data}
    try:
        await call("POST", f"{env('POLICY_API', 'http://localhost:8080')}/v1/audit/events", headers=service_headers(), json_body=body)
    except HTTPException:
        pass


GITHUB_REPO = re.compile(r"(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)([\w.-]+)/([\w.-]+?)(?:\.git)?/?")


def repo_in_org(repo: str, org: str) -> str:
    m = GITHUB_REPO.fullmatch(repo)
    if not m or m.group(1).lower() != org.lower() or m.group(2) in (".", ".."):
        raise HTTPException(403, f"agents may only work on repositories in the {org} GitHub organization")
    return m.group(2)


class LaunchReq(BaseModel):
    agent: str = Field(pattern="^(claude|codex)$")
    repo: str = Field(min_length=1, max_length=1024)
    environment: str = "development"
    device_id: str = Field(default="unknown", max_length=128)


@app.get("/health")
def health():
    return {"status": "ok"}


async def provision(s: dict, credential_auth: dict, org: str, repo_name: str, agent: str) -> tuple[str, str, bool]:
    """Providers, sandbox and clone for a session the Policy API issued. `credential_auth` is what the
    broker sees: the user's own token, or for job sessions the orchestrator's (jobs may run with no person)."""
    policy_org = (s["policy"].get("github") or {}).get("org")
    if policy_org and policy_org.lower() != org.lower():
        raise HTTPException(500, f"policy github.org {policy_org!r} does not match the gateway's github-org profile ({org!r})")

    # Provider names and profiles come from the Policy API; the gateway interceptor allows exactly
    # this set, so the orchestrator cannot attach anything else even by mistake.
    token = s["session_token"]
    broker = env("CREDENTIAL_BROKER", "http://localhost:8081")

    async def credentials(profile):
        if profile == "tether-llm":
            return {"ANTHROPIC_AUTH_TOKEN": token, "TETHER_LLM_TOKEN": token}
        if profile == "tether-policy":
            return {"TETHER_SESSION_TOKEN": token}
        if profile == "tether-aws":
            a = await call("POST", f"{broker}/v1/credentials/aws", headers=credential_auth, json_body={"session_id": s["session_id"]})
            return {"AWS_ACCESS_KEY_ID": a["AccessKeyId"], "AWS_SECRET_ACCESS_KEY": a["SecretAccessKey"], "AWS_SESSION_TOKEN": a["SessionToken"]}
        if profile == "github-org":
            g = await call("POST", f"{broker}/v1/credentials/github", headers=credential_auth, json_body={"session_id": s["session_id"]})
            return {"GITHUB_TOKEN": g["token"], "GH_TOKEN": g["token"]}
        raise HTTPException(500, f"unknown provider profile {profile!r}")

    providers = {pname: (profile, await credentials(profile)) for pname, profile in s["providers"].items()}

    name = s["sandbox_name"]
    workdir = f"/workspace/{repo_name}"
    labels = {"managed-by": "tether-orchestrator", "session": s["session_id"], "user": re.sub(r"[^a-z0-9-]", "-", s["user_id"].lower())[:63]}
    if s.get("job"):
        labels["job"] = s["job"]["id"]
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, dir=env("ORCHESTRATOR_STATE_DIR") or None) as f:
        yaml.safe_dump(s["openshell_policy"], f, sort_keys=False)
        policy_file = f.name
    try:
        exists = await openshell.sandbox_exists(name)
        for pname, (profile, creds) in providers.items():
            await openshell.upsert_provider(pname, profile, creds)
        if exists:
            await openshell.set_policy(name, policy_file)
        else:
            await openshell.create_sandbox(name, policy_file, list(providers), labels)
            rc, _, err = await openshell.exec(name, ["git", "clone", "--", f"https://github.com/{org}/{repo_name}.git", workdir])
            if rc != 0:
                raise OpenShellError(f"git clone failed in sandbox: {err.strip()[-500:]}")
    except OpenShellError as e:
        await audit("sandbox.create", s, {"sandbox_name": name, "error": str(e)}, success=False)
        raise HTTPException(502, str(e))
    finally:
        os.unlink(policy_file)
    await audit("sandbox.reuse" if exists else "sandbox.create", s, {"sandbox_name": name, "agent": agent, "providers": sorted(providers),
                                                                    **({"job_id": s["job"]["id"]} if s.get("job") else {})})
    return name, workdir, exists


@app.post("/v1/launch")
async def launch(req: LaunchReq, request: Request):
    user_token = bearer(request)
    org = env("GITHUB_ORG")
    if not org:
        raise HTTPException(500, "GITHUB_ORG is not configured")
    repo_name = repo_in_org(req.repo, org)
    # Device identity comes from the mTLS proxy in front of the orchestrator, never from the body.
    cert_device = request.headers.get(env("DEVICE_ID_HEADER")) if env("DEVICE_ID_HEADER") else None
    if env("DEVICE_ID_HEADER") and not cert_device:
        raise HTTPException(401, "client certificate required")
    s = await call("POST", f"{env('POLICY_API', 'http://localhost:8080')}/v1/agent/sessions", headers=service_headers(),
                   json_body={"user_token": user_token, "device_id": cert_device or req.device_id, "device_verified": bool(cert_device),
                              "agent": req.agent, "repo": req.repo, "environment": req.environment})
    name, workdir, _ = await provision(s, {"Authorization": f"Bearer {user_token}"}, org, repo_name, req.agent)
    ticket = secrets.token_urlsafe(32)
    state.tickets[ticket] = Ticket(s["user_id"], s["session_id"], s.get("device_id") or req.device_id, name, req.agent, workdir, time.monotonic() + TICKET_SECONDS)
    return {"session_id": s["session_id"], "sandbox_name": name, "policy_version": s["policy_version"], "ticket": ticket,
            "attach_path": "/v1/attach", "ticket_expires_in": TICKET_SECONDS}


@app.websocket("/v1/attach")
async def attach(ws: WebSocket, ticket: str, rows: int = 24, cols: int = 80):
    # One-time, short-lived ticket from /v1/launch: the terminal can only reach that sandbox.
    t = state.tickets.pop(ticket, None)
    if not t or t.expires < time.monotonic():
        await ws.close(code=4401)
        return
    await ws.accept()
    agent_env = {"ANTHROPIC_BASE_URL": f"{env('LLM_GATEWAY_URL')}/anthropic", "OPENAI_BASE_URL": f"{env('LLM_GATEWAY_URL')}/openai/v1",
                 "TETHER_POLICY_API": env("POLICY_API_PUBLIC_URL")}
    relay = Relay(openshell.exec_tty_argv(t.sandbox, AGENTS[t.agent], t.workdir, agent_env), rows, cols)
    await relay.start()
    state.relays[t.session_id] = relay
    s = {"session_id": t.session_id, "user_id": t.user_id, "device_id": t.device_id}
    try:
        code = await relay.pump(ws)
    finally:
        state.relays.pop(t.session_id, None)
    await audit("agent.exit", s, {"sandbox_name": t.sandbox, "returncode": code}, success=code == 0)
    try:
        await ws.send_text(json.dumps({"type": "exit", "code": code}))
        await ws.close()
    except RuntimeError:
        pass


# --- local-LLM agent jobs (ADR 0001, D1) ------------------------------------------------

DEFAULT_LOCAL_AGENT = ["tether-agent"]
# Outside the repository (/workspace/<repo>), so the agent cannot commit it. A repository with this
# exact name would make the write fail (it is a directory), never land the task inside the repo.
TASK_FILE = "/workspace/.tether-task"


def local_agent_argv() -> list[str]:
    # JSON list, e.g. ["tether-agent", "--non-interactive"]; the agent reads its task from TETHER_TASK_FILE.
    raw = env("LOCAL_AGENT_COMMAND")
    return json.loads(raw) if raw else DEFAULT_LOCAL_AGENT


async def end_session(s: dict):
    try:
        await call("POST", f"{env('POLICY_API', 'http://localhost:8080')}/v1/agent/sessions/{s['session_id']}/end", headers=service_headers())
    except HTTPException as e:
        log.warning("could not end job session %s: %s", s["session_id"], e.detail)


async def run_job(s: dict, name: str, workdir: str):
    """Run the approved task once, non-interactively, then delete the sandbox and end the session."""
    job = s["job"]
    # The task goes in through stdin to a file, never argv/--env: those show up in process listings
    # on the orchestrator host and in the sandbox. Only its path is passed to the agent.
    agent_env = {"OPENAI_BASE_URL": f"{env('LLM_GATEWAY_URL')}/local/v1", "TETHER_POLICY_API": env("POLICY_API_PUBLIC_URL"),
                 "TETHER_MODEL": job["model"], "TETHER_TASK_FILE": TASK_FILE, "TETHER_JOB": job["id"]}
    result = {"sandbox_name": name, "job_id": job["id"], "trigger": job["trigger"], "triggered_by": job["triggered_by"],
              "returncode": None, "timed_out": False}

    async def execute():
        await openshell.write_file(name, TASK_FILE, job["task"].encode())
        return await openshell.exec(name, local_agent_argv(), workdir, env=agent_env)
    try:
        rc, _, _ = await asyncio.wait_for(execute(), timeout=job["max_runtime_seconds"])
        result["returncode"] = rc
    except asyncio.TimeoutError:
        result["timed_out"] = True
    except OpenShellError as e:
        result["error"] = str(e)
    finally:
        await audit("agent.exit", s, result, success=result["returncode"] == 0)
        try:
            # Deleting the sandbox also stops an agent that outlived its runtime.
            await openshell.delete_sandboxes([name])
            await audit("sandbox.delete", s, {"sandbox_name": name, "job_id": job["id"], "reason": "job run finished"})
        except OpenShellError as e:
            log.error("job sandbox %s was not deleted: %s", name, e)
        await end_session(s)
        state.runs.pop(s["session_id"], None)


async def start_job(job_id: str, trigger: str, user_token: str = "", device_id: str = "scheduler", device_verified: bool = False) -> dict:
    org = env("GITHUB_ORG")
    if not org:
        raise HTTPException(500, "GITHUB_ORG is not configured")
    # Whether the job is approved, whose it is and whether it is due are the Policy API's decisions.
    s = await call("POST", f"{env('POLICY_API', 'http://localhost:8080')}/v1/agent/sessions", headers=service_headers(),
                   json_body={"user_token": user_token, "device_id": device_id, "device_verified": device_verified, "agent": "local", "repo": "-",
                              "job_id": job_id, "trigger": trigger})
    try:
        repo_name = repo_in_org(s["job"]["repo"], org)
        name, workdir, _ = await provision(s, service_headers(), org, repo_name, "local")
    except BaseException:
        await end_session(s)
        raise
    state.runs[s["session_id"]] = asyncio.create_task(run_job(s, name, workdir))
    return {"job_id": job_id, "session_id": s["session_id"], "sandbox_name": name, "trigger": trigger, "status": "started"}


@app.post("/v1/jobs/{job_id}/run")
async def run_job_now(job_id: str, request: Request):
    """A person runs an approved job (its owner or an administrator, checked by the Policy API)."""
    user_token = bearer(request)
    cert_device = request.headers.get(env("DEVICE_ID_HEADER")) if env("DEVICE_ID_HEADER") else None
    if env("DEVICE_ID_HEADER") and not cert_device:
        raise HTTPException(401, "client certificate required")
    return await start_job(job_id, "manual", user_token, cert_device or "unknown", bool(cert_device))


async def run_due_jobs() -> list[dict]:
    due = await call("GET", f"{env('POLICY_API', 'http://localhost:8080')}/v1/agent/jobs/due", headers=service_headers())
    started = []
    for j in due["jobs"]:
        try:
            started.append(await start_job(j["id"], "schedule"))
        except HTTPException as e:  # e.g. still running (409); the next tick tries again
            log.warning("scheduled job %s not started: %s", j["id"], e.detail)
    return started


async def scheduler():
    while True:
        try:
            await run_due_jobs()
        except Exception:
            log.exception("job scheduler tick failed")
        await asyncio.sleep(int(env("JOB_SCHEDULER_SECONDS", "60")))


class RevokeReq(BaseModel):
    session_id: str | None = None
    user_id: str | None = None
    device_id: str | None = None
    job_id: str | None = None
    all: bool = False
    reason: str = Field(min_length=1, max_length=500)


@app.post("/v1/admin/revoke")
async def revoke(req: RevokeReq, request: Request):
    """Incident-response kill switch, end to end:
    1. Policy API expires the session tokens (permission checks, LLM gateway, broker all refuse),
       authorized by the caller's own admin token.
    2. Live terminals for those sessions are cut.
    3. Their sandboxes are deleted on the gateway.
    4. The broker revokes already-issued AWS sessions and GitHub tokens.
    """
    admin_token = bearer(request)
    r = await call("POST", f"{env('POLICY_API', 'http://localhost:8080')}/v1/admin/sessions/revoke",
                   headers={"Authorization": f"Bearer {admin_token}"}, json_body=req.model_dump())
    sessions = r["sessions"]
    for s in sessions:
        relay = state.relays.get(s["session_id"])
        if relay:
            relay.kill()
    for k in [k for k, t in state.tickets.items() if t.session_id in {s["session_id"] for s in sessions}]:
        state.tickets.pop(k, None)
    result = {"revoked_sessions": len(sessions), "sandboxes_deleted": [], "errors": []}
    sandboxes = sorted({s["sandbox_name"] for s in sessions})
    try:
        await openshell.delete_sandboxes(sandboxes)
        result["sandboxes_deleted"] = sandboxes
        for s in sessions:
            await audit("sandbox.delete", s, {"sandbox_name": s["sandbox_name"], "reason": req.reason})
    except OpenShellError as e:
        result["errors"].append(f"sandbox delete: {e}")
    if sessions:
        try:
            b = await call("POST", f"{env('CREDENTIAL_BROKER', 'http://localhost:8081')}/v1/admin/revoke", headers=service_headers(),
                           json_body={"session_ids": [s["session_id"] for s in sessions], "reason": req.reason})
            result["credentials"] = b
        except HTTPException as e:
            result["errors"].append(f"credential revoke: {e.detail}")
    if result["errors"]:
        # Partial containment must be loud: the caller has to finish it by hand (runbook).
        raise HTTPException(502, result)
    return result
