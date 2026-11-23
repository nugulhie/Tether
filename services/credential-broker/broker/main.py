"""Credential broker: issues short-lived, session-scoped credentials to agent sessions.

The caller presents its own OIDC token and a session id. The broker asks the Policy
API for that session with the same token, so only the session owner can obtain
credentials, and only what the session's policy grants is issued. Developer
long-lived keys are never handed out.
"""
import json
import os
import re
import time
from datetime import datetime, timezone

import boto3
import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from . import store

app = FastAPI(title="Company Agent Credential Broker")

GITHUB_API = "https://api.github.com"
GITHUB_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

# Overridable in tests.
sts_client = lambda: boto3.client("sts")  # noqa: E731
iam_client = lambda: boto3.client("iam")  # noqa: E731
REVOKE_POLICY = "CompanyAgentRevokedSessions"
http_transport = None


def env(name, default=""):
    return os.environ.get(name, default)


class CredentialReq(BaseModel):
    session_id: str


def http():
    return httpx.Client(timeout=10, transport=http_transport)


def load_session(request: Request, session_id: str) -> dict:
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    with http() as c:
        r = c.get(f"{env('POLICY_API', 'http://localhost:8080')}/v1/agent/sessions/{session_id}", headers={"Authorization": auth})
    if r.status_code in (401, 403, 404, 409, 410):
        # Pass the Policy API's verdict through: unauthenticated, not owner, policy changed, expired.
        raise HTTPException(r.status_code, r.json().get("detail", "session rejected"))
    r.raise_for_status()
    s = r.json()
    if s["environment"] == "production":
        raise HTTPException(403, "agents never receive production credentials")
    return s


def audit(s, kind, success, data):
    token = env("CREDENTIAL_BROKER_TOKEN")
    if not token:
        return
    body = {"event_type": "credential.issue", "session_id": s["session_id"], "user_id": s["user_id"], "device_id": s["device_id"],
            "success": success, "message": f"{kind} credential {'issued' if success else 'denied'}", "data": {"kind": kind, **data}}
    with http() as c:
        c.post(f"{env('POLICY_API', 'http://localhost:8080')}/v1/audit/events", json=body, headers={"Authorization": f"Bearer {token}"}).raise_for_status()


def seconds_left(s):
    return int((datetime.fromisoformat(s["expires_at"]) - datetime.now(timezone.utc)).total_seconds())


# STS session tag values: letters, digits, spaces and _.:/=+-@ only, max 256 chars.
def tag_value(v):
    return re.sub(r"[^\w .:/=+\-@]", "_", str(v))[:256]


# SourceIdentity: 2-64 chars of [\w+=,.@-]. It is immutable across role chaining and
# shows up in CloudTrail, so every API call made with these credentials names the user.
def source_identity(user):
    return re.sub(r"[^A-Za-z0-9_+=,.@-]", "_", user)[:64].ljust(2, "_")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/credentials/aws")
def aws_credentials(req: CredentialReq, request: Request):
    s = load_session(request, req.session_id)
    grant = s["policy"].get("aws") or {}
    if not grant.get("role"):
        audit(s, "aws", False, {"reason": "AWS_NOT_GRANTED"})
        raise HTTPException(403, "policy grants no AWS role")
    # Never outlive the agent session; STS minimum is 900 seconds.
    duration = min(grant.get("duration_seconds", 3600), seconds_left(s))
    if duration < 900:
        raise HTTPException(410, "session expires too soon for AWS credentials; start a new session")
    tags = {"user": s["user_id"], "device": s["device_id"], "repo": s["repo"], "agent": s["agent"], "session_id": s["session_id"]}
    out = sts_client().assume_role(
        RoleArn=grant["role"],
        RoleSessionName=f"agent-{s['session_id']}"[:64],
        DurationSeconds=duration,
        SourceIdentity=source_identity(s["user_id"]),
        Tags=[{"Key": k, "Value": tag_value(v)} for k, v in tags.items()],
    )
    c = out["Credentials"]
    store.record_aws(s["session_id"], grant["role"], c["Expiration"].timestamp())
    audit(s, "aws", True, {"role": grant["role"], "duration_seconds": duration, "assumed_role": out["AssumedRoleUser"]["Arn"]})
    # Same shape as the AWS CLI credential_process output.
    return {"Version": 1, "AccessKeyId": c["AccessKeyId"], "SecretAccessKey": c["SecretAccessKey"],
            "SessionToken": c["SessionToken"], "Expiration": c["Expiration"].isoformat()}


def github_repo(repo):
    m = re.fullmatch(r"(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)([\w.-]+)/([\w.-]+?)(?:\.git)?/?", repo)
    if not m:
        raise HTTPException(422, f"session repo is not a github.com repository: {repo!r}")
    return m.group(1), m.group(2)


def app_jwt():
    app_id, key = env("GITHUB_APP_ID"), env("GITHUB_APP_PRIVATE_KEY")
    if not key and env("GITHUB_APP_PRIVATE_KEY_FILE"):
        with open(env("GITHUB_APP_PRIVATE_KEY_FILE")) as f:
            key = f.read()
    if not (app_id and key):
        raise HTTPException(503, "GitHub App is not configured")
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": app_id}, key, algorithm="RS256")


@app.post("/v1/credentials/github")
def github_credentials(req: CredentialReq, request: Request):
    s = load_session(request, req.session_id)
    perms = (s["policy"].get("github") or {}).get("permissions")
    if not perms:
        audit(s, "github", False, {"reason": "GITHUB_NOT_GRANTED"})
        raise HTTPException(403, "policy grants no GitHub access")
    owner, name = github_repo(s["repo"])
    if not store.fernet():
        raise HTTPException(503, "BROKER_ENCRYPTION_KEY is not configured: refusing to issue tokens that could not be revoked")
    headers = {**GITHUB_HEADERS, "Authorization": f"Bearer {app_jwt()}"}
    with http() as c:
        r = c.get(f"{GITHUB_API}/repos/{owner}/{name}/installation", headers=headers)
        if r.status_code == 404:
            raise HTTPException(403, f"GitHub App is not installed on {owner}/{name}")
        r.raise_for_status()
        # Token is limited to this one repository and to the policy's permissions.
        r = c.post(f"{GITHUB_API}/app/installations/{r.json()['id']}/access_tokens", headers=headers,
                   json={"repositories": [name], "permissions": perms})
        r.raise_for_status()
    t = r.json()
    store.record_github(s["session_id"], t["token"], datetime.fromisoformat(t["expires_at"].replace("Z", "+00:00")).timestamp())
    audit(s, "github", True, {"repository": f"{owner}/{name}", "permissions": t.get("permissions", perms), "expires_at": t["expires_at"]})
    return {"token": t["token"], "expires_at": t["expires_at"], "repository": f"{owner}/{name}", "permissions": t.get("permissions", perms)}


# --- kill switch ----------------------------------------------------------------

class RevokeReq(BaseModel):
    session_ids: list[str] = Field(min_length=1, max_length=10000)
    reason: str = Field(min_length=1, max_length=500)


def role_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def deny_revoked_policy(session_ids):
    # Session tags become principal tags on the assumed-role session, so this denies
    # every call made with credentials issued to these sessions, immediately.
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyRevokedAgentSessions", "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"StringEquals": {"aws:PrincipalTag/session_id": session_ids}}}]}


@app.post("/v1/admin/revoke")
def revoke(req: RevokeReq, request: Request):
    """Called by the orchestrator's kill switch after the Policy API expired the sessions."""
    expected = env("ORCHESTRATOR_TOKEN")
    if not expected or request.headers.get("authorization", "") != f"Bearer {expected}":
        raise HTTPException(403, "only the orchestrator may revoke credentials")
    result = {"aws_sessions_denied": 0, "aws_roles": [], "github_tokens_revoked": 0, "errors": []}
    roles = set()
    for rec in store.issued(req.session_ids):
        if rec["kind"] == "aws":
            store.mark_revoked(rec["session_id"], rec["role_arn"], rec["expires_at"])
            roles.add(rec["role_arn"])
            result["aws_sessions_denied"] += 1
        elif rec["kind"] == "github" and rec["expires_at"] > time.time():
            with http() as c:
                r = c.delete(f"{GITHUB_API}/installation/token", headers={**GITHUB_HEADERS, "Authorization": f"Bearer {rec['token']}"})
            if r.status_code in (204, 401):  # 401: already revoked or expired
                store.forget_github(rec["session_id"])
                result["github_tokens_revoked"] += 1
            else:
                result["errors"].append(f"github token for {rec['session_id']}: HTTP {r.status_code}")
    for arn in sorted(roles):
        live = store.revoked_live(arn)
        try:
            iam_client().put_role_policy(RoleName=role_name(arn), PolicyName=REVOKE_POLICY, PolicyDocument=json.dumps(deny_revoked_policy(live)))
            result["aws_roles"].append(arn)
        except Exception as e:  # noqa: BLE001 - reported to the caller, who must finish by hand
            result["errors"].append(f"aws deny policy on {arn}: {e}")
    if result["errors"]:
        raise HTTPException(502, result)
    return result
