#!/usr/bin/env python3
"""Release gate smoke test (ADR 0002, A-6): the control plane as built images, talking to each other.

    make smoke        # dev-env, compose up (infra/ci/compose.smoke.yml), this script, compose down

Development mode (AUTH_MODE=dev, dev-* service tokens), no OpenShell, no GPU, no provider keys. It proves
what unit tests cannot: the images start, migrations run on Postgres, and the services find and
authenticate each other. The staging e2e (infra/staging/50-e2e.py) covers sandboxes on a real host.
Stdlib only. Exit status: the number of failed checks.
"""
import json
import sys
import time
import urllib.error
import urllib.request

POLICY_API, BROKER, GATEWAY, ORCHESTRATOR = (f"http://127.0.0.1:{p}" for p in (8080, 8081, 8082, 8083))
ADMIN = "dev:ci-admin:tether-admins"
failures = []


def check(name, ok, detail=""):
    print(f"[{'ok' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def call(method, url, token=None, body=None):
    headers = {"content-type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})}
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"null")
        except ValueError:
            return e.code, raw.decode(errors="replace")


def wait_healthy(name, base, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if call("GET", f"{base}/health")[0] == 200:
                check(f"{name} is up", True)
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(2)
    check(f"{name} is up", False, f"no 200 from {base}/health within {seconds}s")
    return False


def main():
    up = [wait_healthy(n, b) for n, b in (("policy-api", POLICY_API), ("credential-broker", BROKER),
                                          ("llm-gateway", GATEWAY), ("sandbox-orchestrator", ORCHESTRATOR))]
    if not all(up):
        return
    status, b = call("GET", f"{POLICY_API}/v1/policies/bundle/current", ADMIN)
    check("policy-api: repository policies loaded into migrated Postgres", status == 200 and bool(b.get("active")), f"{status} {b}")

    status, s = call("POST", f"{POLICY_API}/v1/agent/sessions", "dev-orchestrator-token",
                     {"user_token": "dev:ci-user", "device_id": "ci", "agent": "claude",
                      "repo": "git@github.com:your-org/repo.git", "environment": "development"})
    check("policy-api: session issued for the orchestrator", status == 200 and "session_token" in s, f"{status} {s}")
    if status != 200:
        return

    # The gateway resolves the session with the Policy API (service token), then refuses: no provider key in CI.
    status, r = call("POST", f"{GATEWAY}/anthropic/v1/messages", s["session_token"],
                     {"model": "claude-opus-5-5", "max_tokens": 8, "messages": [{"role": "user", "content": "ping"}]})
    check("llm-gateway: session resolved through the Policy API", status == 503 and "not configured on this gateway" in json.dumps(r), f"{status} {r}")
    status, r = call("POST", f"{GATEWAY}/anthropic/v1/messages", "ast_not-a-session-token-at-all",
                     {"model": "claude-opus-5-5", "max_tokens": 8, "messages": []})
    check("llm-gateway: unknown session token refused", status == 401, f"{status} {r}")

    status, ev = call("GET", f"{POLICY_API}/v1/audit/events?limit=5000", "dev-siem-token")
    kinds = {e.get("metadata", {}).get("event_code") for e in ev.get("events", [])} if status == 200 else set()
    check("audit: session.create and llm.denied recorded", {"session.create", "llm.denied"} <= kinds, f"{status} {sorted(k for k in kinds if k)}")
    status, chain = call("GET", f"{POLICY_API}/v1/admin/audit/chain", ADMIN)
    check("audit: hash chain verifies", status == 200 and chain.get("ok") is True, f"{status} {chain}")


main()
print(f"\n{len(failures)} failed" + (": " + ", ".join(failures) if failures else ""))
sys.exit(len(failures))
