import asyncio
import hashlib
import logging
import os
import posixpath
import re
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, exists, func, or_, select
from policy_compiler import PolicyError, compile_policy, policy_hash, static_part
from policy_compiler import bundle as bundles
from . import ocsf
from .auth import Principal, SESSION_TOKEN_PREFIX, bearer, env, hash_token, is_admin, new_session_token, service_principal, verified_device, verify_user_token
from .db import Session, migrate
from .models import AgentJob, AgentSession, AuditEvent, ContentHold, GuardrailBypass, LlmContent, Policy, PolicyBundle, SessionToken, now

WORKSPACE="/workspace"
Id=Field(min_length=1,max_length=128)
class SessionReq(BaseModel):
    # Sent by the sandbox orchestrator on the user's behalf. The user's own OIDC token proves
    # who the user is (the orchestrator cannot mint sessions for anyone without one); the device
    # identity comes from the mTLS proxy in front of the orchestrator.
    user_token:str=Field(default="",max_length=8192); device_id:str=Id; device_verified:bool=False
    agent:str=Field(min_length=1,max_length=64); repo:str=Field(min_length=1,max_length=1024); environment:str="development"
    # Local-agent jobs: an approved job, run by a person (their user_token) or by the schedule (no user).
    job_id:str|None=Field(default=None,max_length=36); trigger:str|None=Field(default=None,pattern="^(manual|schedule)$")
class PermissionReq(BaseModel):
    # Identity (user, device, repo, environment) comes from the session token, not the body.
    action:str; resource:str; context:dict=Field(default_factory=dict)
class AuditReq(BaseModel):
    event_type:str; session_id:str|None=None; success:bool=True; message:str=""; data:dict=Field(default_factory=dict)
    # Only honored for service callers, which report on behalf of a user.
    user_id:str|None=None; device_id:str|None=None

def utc(dt): return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def authenticate(request:Request)->Principal:
    token=bearer(request)
    if token.startswith(SESSION_TOKEN_PREFIX):
        with Session() as db:
            t=db.scalar(select(SessionToken).where(SessionToken.token_hash==hash_token(token)))
            if not t or utc(t.expires_at)<=now(): raise HTTPException(401,"invalid or expired session token")
            s=db.get(AgentSession,t.session_id)
            return Principal(kind="session",user_id=s.user_id,device_id=s.device_id,device_verified=t.device_verified,session_id=s.id)
    svc=service_principal(token)
    if svc: return svc
    device=verified_device(request); user,groups=verify_user_token(token)
    return Principal(kind="user",user_id=user,groups=groups,device_id=device,device_verified=device is not None)

def require(*kinds,service=()):
    """kinds: principal kinds allowed; "admin" admits users in ADMIN_GROUPS; service limits which services."""
    services=(service,) if isinstance(service,str) else service
    def dep(p:Principal=Depends(authenticate)):
        ok=p.kind in kinds and not (p.kind=="service" and services and p.user_id not in services)
        if not ok and "admin" in kinds and is_admin(p): ok=True
        if not ok: raise HTTPException(403,f"{p.user_id if p.kind=='service' else p.kind} credentials cannot call this endpoint")
        return p
    return dep

def record(db,event_type,principal,*,source,session_id=None,**kw):
    evt=ocsf.build(event_type,user_id=principal.user_id,device_id=principal.device_id,device_verified=principal.device_verified,session_id=session_id or principal.session_id,source=source,**kw)
    db.add(AuditEvent(event_type=event_type,payload=evt)); ocsf.emit(evt)

# --- policies ---------------------------------------------------------------

def select_policy(db,repo,environment,groups):
    # Highest priority wins; priorities are unique within a bundle. No match -> no session.
    for p in db.scalars(select(Policy).where(Policy.active.is_(True)).order_by(Policy.priority.desc())):
        if bundles.matches({"match":p.match},repo,environment,groups): return p
    return None

def pinned_policy(db,s):
    """The exact policy version a session started with, if it is still active."""
    p=db.get(Policy,(s.policy_id,s.policy_version))
    return p if p and p.active else None

def apply_bundle(db,bundle,*,signed,key_id,publisher):
    try:
        bundles.validate_bundle(bundle)
        # CI cannot know deployment hosts (e.g. GPU inference servers); check them here too.
        for p in bundle["policies"]: compile_policy(bundles.document(p),WORKSPACE,platform())
    except PolicyError as e: raise HTTPException(422,str(e))
    last=db.scalar(select(func.max(PolicyBundle.serial))) or 0
    # Refuse replays of older (still validly signed) bundles.
    if bundle["serial"]<=last: raise HTTPException(409,f"bundle serial {bundle['serial']} is not newer than {last}")
    changed,rollbacks=[],[]
    for p in bundle["policies"]:
        doc=bundles.document(p); row=db.get(Policy,(p["policy_id"],p["version"]))
        if row and row.bundle_serial is None:
            # A row seeded by pre-bundle code was never published: replace it with the published content.
            row.document,row.match,row.priority,row.bundle_serial=doc,p["match"],p["priority"],bundle["serial"]; changed.append(f"{p['policy_id']}@{p['version']}")
        elif row:
            if (row.document,row.match,row.priority)!=(doc,p["match"],p["priority"]): raise HTTPException(409,f"{p['policy_id']} v{p['version']} changed without a version bump")
            # Re-activating an identical, previously published older version is a reviewed
            # rollback (a git revert); it is allowed and recorded explicitly.
            latest=db.scalar(select(func.max(Policy.version)).where(Policy.id==p["policy_id"],Policy.bundle_serial.is_not(None)))
            if p["version"]<latest and not row.active: rollbacks.append(f"{p['policy_id']}@{latest}->{p['version']}")
        else:
            # Rows seeded by pre-bundle code (bundle_serial NULL) were never published; ignore them.
            latest=db.scalar(select(func.max(Policy.version)).where(Policy.id==p["policy_id"],Policy.bundle_serial.is_not(None))) or 0
            if p["version"]<latest: raise HTTPException(409,f"{p['policy_id']} v{p['version']} is older than published v{latest}")
            row=Policy(id=p["policy_id"],version=p["version"],document=doc,match=p["match"],priority=p["priority"],bundle_serial=bundle["serial"]); db.add(row); changed.append(f"{p['policy_id']}@{p['version']}")
        row.active=True
    keep={(p["policy_id"],p["version"]) for p in bundle["policies"]}
    for row in db.scalars(select(Policy).where(Policy.active.is_(True))):
        if (row.id,row.version) not in keep: row.active=False
    digest=bundles.sha256(bundle)
    db.add(PolicyBundle(serial=bundle["serial"],git_commit=bundle.get("git_commit",""),sha256=digest,signed=signed,key_id=key_id))
    record(db,"policy.publish",publisher,source="policy-api",data={"serial":bundle["serial"],"git_commit":bundle.get("git_commit"),"sha256":digest,"signed":signed,"key_id":key_id,"new_versions":changed,"rollbacks":rollbacks,"active":sorted(f"{i}@{v}" for i,v in keep)})
    return {"serial":bundle["serial"],"sha256":digest,"new_versions":changed,"rollbacks":rollbacks}

def bundle_public_key():
    if env("POLICY_BUNDLE_PUBLIC_KEY"): return env("POLICY_BUNDLE_PUBLIC_KEY").encode()
    if env("POLICY_BUNDLE_PUBLIC_KEY_FILE"): return Path(env("POLICY_BUNDLE_PUBLIC_KEY_FILE")).read_bytes()
    return None

def load_dev_policies():
    """AUTH_MODE=dev only: publish POLICY_DIR as an unsigned bundle when its content changed."""
    if env("AUTH_MODE","oidc")!="dev" or not env("POLICY_DIR"): return
    with Session() as db:
        policies=bundles.load_dir(env("POLICY_DIR"))
        last=db.scalar(select(PolicyBundle).order_by(PolicyBundle.serial.desc()).limit(1))
        b={"format":bundles.BUNDLE_FORMAT,"serial":(last.serial if last else 0)+1,"git_commit":"local","policies":policies}
        if last and last.git_commit=="local" and last.sha256==bundles.sha256({**b,"serial":last.serial}): return
        apply_bundle(db,b,signed=False,key_id=None,publisher=Principal(kind="service",user_id="local-policy-dir")); db.commit()


@asynccontextmanager
async def lifespan(app):
    # A bad retention setting stops startup rather than being guessed at (see content_retention_days).
    content_retention_days(); interval=content_purge_interval()
    # Production can set MIGRATE_ON_STARTUP=0 and run `alembic upgrade head` as a release step.
    if env("MIGRATE_ON_STARTUP","1")=="1": migrate()
    load_dev_policies()
    task=asyncio.create_task(purge_loop(interval)) if interval else None
    try: yield
    finally:
        if task:
            task.cancel()
            with suppress(asyncio.CancelledError): await task

app=FastAPI(title="Company Agent Policy API",lifespan=lifespan)

def platform():
    """Deployment endpoints every sandbox can reach (with its agent binaries only)."""
    return {"llm_gateway_host":env("PLATFORM_LLM_GATEWAY_HOST"),"policy_api_host":env("PLATFORM_POLICY_API_HOST"),
            # Self-hosted inference servers: only the LLM gateway may reach them, never a sandbox.
            "local_inference_hosts":env("PLATFORM_LOCAL_INFERENCE_HOSTS")}

def sandbox_providers(sandbox,doc):
    """OpenShell provider instances a sandbox may have, as {name: profile id}. The orchestrator
    creates exactly these and the gateway interceptor allows nothing else."""
    out={f"{sandbox}-llm":"company-llm",f"{sandbox}-policy":"company-policy"}
    if (doc.get("aws") or {}).get("role"): out[f"{sandbox}-aws"]="company-aws"
    if (doc.get("github") or {}).get("permissions"): out[f"{sandbox}-github"]="github-org"
    return out

def grants(doc):
    return {"aws":doc.get("aws") or {},"github":doc.get("github") or {}}

def slug(s,n):
    return re.sub(r"[^a-z0-9]+","-",s.lower()).strip("-")[:n].strip("-")

def sandbox_name(user_id,repo,static_hash):
    # Same user + repo + static policy -> same sandbox, so the launcher can reuse it.
    # Only sections OpenShell locks at creation (filesystem, landlock, process) and the
    # credential providers count: network changes are applied live with `openshell policy set`.
    u=slug(user_id,32)
    if not u: raise HTTPException(422,"user_id must contain at least one alphanumeric character")
    return f"agent-{u}-{hashlib.sha256(repo.encode()).hexdigest()[:8]}-{static_hash[:8]}"

def norm(path):
    # posixpath.normpath keeps a leading "//", so collapse it explicitly.
    return posixpath.normpath("/"+path.lstrip("/"))

def under(path,roots):
    path=norm(path)
    return any(path==r or path.startswith(r.rstrip("/")+"/") for r in map(norm,roots))

def host_of(resource):
    r=resource if "://" in resource else "//"+resource
    return (urlsplit(r).hostname or "").rstrip(".")

@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/v1/agent/sessions")
def create_session(req:SessionReq,orch:Principal=Depends(require("service",service="sandbox-orchestrator"))):
    # Only the orchestrator receives session tokens: it injects them into the sandbox as an
    # OpenShell credential, so no developer machine ever holds one.
    with Session() as db:
        job=None; ttl=int(env("SESSION_TTL_SECONDS","43200"))
        if req.job_id or req.agent==LOCAL_AGENT:
            job,p=job_session_principal(db,req)
            req=req.model_copy(update={"agent":LOCAL_AGENT,"repo":job.repo,"environment":job.environment})
            # A job session lives only as long as one run may take.
            ttl=min(ttl,job.max_runtime_seconds+JOB_SESSION_GRACE_SECONDS)
        else:
            user,groups=verify_user_token(req.user_token)
            p=Principal(kind="user",user_id=user,groups=groups,device_id=req.device_id,device_verified=req.device_verified)
        pol=select_policy(db,req.repo,req.environment,p.groups)
        if not pol: raise HTTPException(403,f"no policy allows {req.agent} on {bundles.normalize_repo(req.repo)} in {req.environment}")
        try: compiled=compile_policy(pol.document,WORKSPACE,platform())
        except PolicyError as e: raise HTTPException(422,f"policy {pol.id} v{pol.version} is not valid here: {e}")
        g=grants(pol.document)
        phash=policy_hash({"openshell":compiled,"grants":g}); shash=policy_hash({"static":static_part(compiled),"grants":g})
        sid=str(uuid.uuid4())
        # A job always gets its own sandbox, whoever starts it: never a developer's interactive one.
        sandbox=sandbox_name(f"job-{job.id}" if job else p.user_id,req.repo,shash)
        device=p.device_id or req.device_id
        token,token_hash=new_session_token(); expires=now()+timedelta(seconds=ttl)
        job_fields={"job_id":job.id,"trigger":req.trigger,"triggered_by":p.user_id if req.trigger=="manual" else "schedule"} if job else {}
        if job and req.trigger=="schedule": job.last_scheduled_at=now()
        db.add(AgentSession(id=sid,user_id=p.user_id,device_id=device,agent=req.agent,repo=req.repo,environment=req.environment,policy_id=pol.id,policy_version=pol.version,policy_hash=phash,sandbox_name=sandbox,**job_fields))
        db.add(SessionToken(session_id=sid,token_hash=token_hash,device_verified=p.device_verified,expires_at=expires))
        record(db,"session.create",p,source="policy-api",session_id=sid,data={"agent":req.agent,"repo":req.repo,"environment":req.environment,"groups":list(p.groups),"policy_id":pol.id,"policy_version":pol.version,"policy_hash":phash,"sandbox_name":sandbox,**job_fields})
        db.commit()
        out={"session_id":sid,"session_token":token,"expires_at":expires.isoformat(),"user_id":p.user_id,"sandbox_name":sandbox,"policy_id":pol.id,"policy_version":pol.version,"policy":pol.document,"openshell_policy":compiled,"policy_hash":phash,"static_policy_hash":shash,"providers":sandbox_providers(sandbox,pol.document)}
        if job: out["job"]={**job_view(job),**job_fields}
        return out
@app.get("/v1/agent/sessions/{session_id}")
def get_session(session_id:str,p:Principal=Depends(require("user","service",service="sandbox-orchestrator"))):
    # Used by the credential broker with the caller's own token: only the owner can read a session.
    # Job sessions have no person behind a scheduled run, so the orchestrator reads those (and only
    # those) with its own credentials. Session tokens never can: a sandbox must not obtain credentials.
    with Session() as db:
        s=db.get(AgentSession,session_id); t=db.get(SessionToken,session_id)
        mine=s is not None and (bool(s.job_id) if p.kind=="service" else s.user_id==p.user_id)
        if not mine: raise HTTPException(404,"session not found")
        if not t or utc(t.expires_at)<=now(): raise HTTPException(410,"session expired")
        pol=pinned_policy(db,s)
        if not pol: raise HTTPException(409,"policy changed since session start; start a new session")
        return {"session_id":s.id,"user_id":s.user_id,"device_id":s.device_id,"device_verified":t.device_verified,"agent":s.agent,"repo":s.repo,"environment":s.environment,"expires_at":utc(t.expires_at).isoformat(),"policy_id":pol.id,"policy_version":pol.version,"policy_hash":s.policy_hash,"policy":pol.document}

def decide_permission(req,s,doc):
    # Default deny: only the actions listed here can ever be allowed.
    def decide(ok,allow_code,deny_code): return {"decision":"ALLOW" if ok else "DENY","reason_code":allow_code if ok else deny_code}
    if s.environment=="production": return {"decision":"DENY","reason_code":"PRODUCTION_ACCESS_DENIED"}
    if req.resource.startswith("s3://"):
        if "prod" in req.resource: return {"decision":"DENY","reason_code":"PRODUCTION_DATA"}
        return decide(bool(doc.get("aws",{}).get("role")),"AWS_ROLE_GRANTED","AWS_NOT_GRANTED")
    if req.action=="network_connect":
        # Exact host match only, mirroring what OpenShell enforces.
        host=host_of(req.resource).lower()
        return decide(host in {h.lower() for h in doc["network"]["allow"]},"NETWORK_ALLOWED","NETWORK_ENDPOINT_NOT_ALLOWED")
    if req.action=="process_exec":
        name=posixpath.basename(req.resource)
        if name in doc["process"].get("deny",[]): return {"decision":"DENY","reason_code":"PROCESS_DENIED"}
        return decide(name in doc["process"].get("allow",[]),"PROCESS_ALLOWED","PROCESS_NOT_ALLOWED")
    if req.action in ("file_read","file_write"):
        rw=[WORKSPACE,*doc["filesystem"].get("read_write",[])]
        roots=rw if req.action=="file_write" else [*rw,*doc["filesystem"]["read_only"]]
        return decide(req.resource.startswith("/") and under(req.resource,roots),"PATH_ALLOWED","PATH_NOT_ALLOWED")
    return {"decision":"DENY","reason_code":"UNKNOWN_ACTION"}
@app.post("/v1/permissions/check")
def check(req:PermissionReq,p:Principal=Depends(require("session"))):
    with Session() as db:
        s=db.get(AgentSession,p.session_id); pol=pinned_policy(db,s)
        # A superseded policy no longer authorizes anything; the agent must be relaunched.
        r=decide_permission(req,s,pol.document) if pol else {"decision":"DENY","reason_code":"POLICY_SUPERSEDED"}
        r={**r,"policy_id":s.policy_id,"policy_version":s.policy_version}
        record(db,"permission.check",p,source="policy-api",allowed=r["decision"]=="ALLOW",message=r["reason_code"],data={"action":req.action,"resource":req.resource,"repo":s.repo,"environment":s.environment,**r})
        db.commit()
        return r
@app.get("/v1/policies/effective")
def effective(repo:str|None=None,environment:str="development",p:Principal=Depends(require("user","session"))):
    with Session() as db:
        if p.kind=="session":
            pol=pinned_policy(db,db.get(AgentSession,p.session_id))
        else:
            if not repo: raise HTTPException(422,"repo is required")
            pol=select_policy(db,repo,environment,p.groups)
        if not pol: raise HTTPException(404,"no active policy")
        return {"id":pol.id,"version":pol.version,"policy":pol.document}
@app.post("/v1/policies/bundle")
def publish_bundle(envelope:dict=Body(...),p:Principal=Depends(require("service",service="policy-publisher"))):
    key=bundle_public_key()
    if "signature" in envelope:
        if not key: raise HTTPException(500,"POLICY_BUNDLE_PUBLIC_KEY is not configured")
        try: bundle=bundles.verify(envelope,key)
        except PolicyError as e: raise HTTPException(422,str(e))
        signed,key_id=True,envelope.get("key_id")
    elif env("AUTH_MODE","oidc")=="dev" and not key:
        bundle,signed,key_id=envelope.get("bundle",envelope),False,None
    else:
        raise HTTPException(422,"bundle must be signed")
    with Session() as db:
        r=apply_bundle(db,bundle,signed=signed,key_id=key_id,publisher=p); db.commit()
        return r
@app.get("/v1/policies/bundle/current")
def current_bundle(p:Principal=Depends(require("user","service"))):
    with Session() as db:
        b=db.scalar(select(PolicyBundle).order_by(PolicyBundle.serial.desc()).limit(1))
        if not b: raise HTTPException(404,"no bundle published")
        return {"serial":b.serial,"git_commit":b.git_commit,"sha256":b.sha256,"signed":b.signed,"key_id":b.key_id,"loaded_at":utc(b.loaded_at).isoformat(),
                "active":[f"{x.id}@{x.version}" for x in db.scalars(select(Policy).where(Policy.active.is_(True)).order_by(Policy.priority.desc()))]}
@app.post("/v1/audit/events")
def audit(req:AuditReq,p:Principal=Depends(require("user","session","service"))):
    allowed=ocsf.SERVICE_EVENT_TYPES.get(p.user_id,set()) if p.kind=="service" else ocsf.CLIENT_EVENT_TYPES
    if req.event_type not in allowed: raise HTTPException(422,f"{p.kind} callers cannot report {req.event_type!r}")
    with Session() as db:
        session_id=p.session_id or req.session_id
        if p.kind=="service":
            if not req.user_id: raise HTTPException(422,"service events must name user_id")
            actor=Principal(kind="user",user_id=req.user_id,device_id=req.device_id)
        else:
            # A user may only report on their own sessions; actor comes from the token.
            if session_id and p.kind=="user":
                s=db.get(AgentSession,session_id)
                if not s or s.user_id!=p.user_id: raise HTTPException(404,"session not found")
            actor=p
        record(db,req.event_type,actor,source=p.user_id if p.kind=="service" else f"{p.kind}-client",session_id=session_id,success=req.success,message=req.message,data=req.data)
        db.commit()
    return {"accepted":True}

# --- incident response and SIEM ---------------------------------------------

class RevokeReq(BaseModel):
    session_id:str|None=None; user_id:str|None=None; device_id:str|None=None; job_id:str|None=None; all:bool=False; reason:str=Field(min_length=1,max_length=500)

@app.post("/v1/admin/sessions/revoke")
def revoke(req:RevokeReq,p:Principal=Depends(require("admin"))):
    """Kill switch: expire session tokens so permission checks fail and no new credentials are issued.

    Already-issued STS/GitHub credentials stay valid until they expire (<= 1h by default);
    see docs/incident-response.md for stopping sandboxes and revoking those.
    """
    selectors={k:v for k,v in {"session_id":req.session_id,"user_id":req.user_id,"device_id":req.device_id,"job_id":req.job_id}.items() if v}
    if not selectors and not req.all: raise HTTPException(422,"give session_id, user_id, device_id, job_id, or all=true")
    if selectors and req.all: raise HTTPException(422,"all=true cannot be combined with selectors")
    with Session() as db:
        q=select(SessionToken,AgentSession).join(AgentSession,AgentSession.id==SessionToken.session_id)
        for k,v in selectors.items(): q=q.where(getattr(AgentSession,"id" if k=="session_id" else k)==v)
        t0=now(); revoked=[]
        for t,s in db.execute(q):
            if utc(t.expires_at)>t0: t.expires_at=t0; revoked.append({"session_id":s.id,"user_id":s.user_id,"device_id":s.device_id,"sandbox_name":s.sandbox_name})
        record(db,"session.revoke",p,source="policy-api",message=req.reason,data={"selectors":selectors,"all":req.all,"reason":req.reason,"count":len(revoked),"sessions":revoked[:100]})
        db.commit()
        # Full list: the orchestrator tears down every sandbox and credential it names.
        return {"revoked":len(revoked),"sessions":revoked}

@app.get("/v1/audit/events")
def audit_events(after_id:int=0,limit:int=500,p:Principal=Depends(require("admin","service",service="siem"))):
    """Pull API for SIEM collectors: OCSF events with id > after_id, oldest first."""
    limit=max(1,min(int(limit),5000))
    with Session() as db:
        rows=db.scalars(select(AuditEvent).where(AuditEvent.id>after_id).order_by(AuditEvent.id).limit(limit)).all()
        return {"events":[{"id":r.id,**r.payload} for r in rows],"next_after_id":rows[-1].id if rows else after_id}

# --- LLM gateway --------------------------------------------------------------

class IntrospectReq(BaseModel):
    session_token:str=Field(min_length=1,max_length=256)

@app.post("/v1/sessions/introspect")
def introspect(req:IntrospectReq,p:Principal=Depends(require("service",service="llm-gateway"))):
    """Resolve a session token for the LLM gateway: who, which session, and the model grants.

    Only active sessions on a still-active policy version resolve; revoked, expired and
    superseded sessions are refused, which is how the kill switch reaches model access.
    """
    if not req.session_token.startswith(SESSION_TOKEN_PREFIX): raise HTTPException(401,"not a session token")
    with Session() as db:
        t=db.scalar(select(SessionToken).where(SessionToken.token_hash==hash_token(req.session_token)))
        if not t or utc(t.expires_at)<=now(): raise HTTPException(401,"invalid or expired session token")
        s=db.get(AgentSession,t.session_id); pol=pinned_policy(db,s)
        if not pol: raise HTTPException(401,"session policy superseded")
        if s.environment=="production": raise HTTPException(403,"production sessions have no model access")
        bypasses=[b for b in open_bypasses(db) if bypass_applies(b,s,pol)]
        db.commit()  # records expiries noticed by open_bypasses
        return {"session_id":s.id,"user_id":s.user_id,"device_id":s.device_id,"agent":s.agent,"repo":s.repo,"environment":s.environment,
                "policy_id":pol.id,"policy_version":pol.version,"llm":pol.document.get("llm") or {},"expires_at":utc(t.expires_at).isoformat(),
                "guardrails":pol.document.get("guardrails"),"guardrail_bypasses":[bypass_view(b) for b in bypasses]}

# --- prompt and response content (ADR 0001, D5) -----------------------------------

CONTENT_MAX_CHARS=int(os.environ.get("CONTENT_MAX_CHARS",str(16*1024*1024)))

class ContentReq(BaseModel):
    session_id:str=Id; user_id:str=Id; request_id:str=Field(min_length=1,max_length=64)
    direction:str=Field(pattern="^(request|response)$"); content:str=Field(max_length=CONTENT_MAX_CHARS); truncated:bool=False

def content_cipher():
    key=env("CONTENT_ENCRYPTION_KEY")
    # No key, no storage: the gateway then refuses the model request instead of running it unaudited.
    if not key: raise HTTPException(503,"CONTENT_ENCRYPTION_KEY is not configured")
    return Fernet(key)

@app.post("/v1/audit/content")
def store_content(req:ContentReq,p:Principal=Depends(require("service",service="llm-gateway"))):
    """Store one prompt or response body for the LLM gateway. The audit event gets only its id and hash."""
    f=content_cipher(); raw=req.content.encode()
    with Session() as db:
        s=db.get(AgentSession,req.session_id)
        if not s or s.user_id!=req.user_id: raise HTTPException(404,"session not found")
        row=LlmContent(id=str(uuid.uuid4()),session_id=s.id,request_id=req.request_id,direction=req.direction,
                       sha256=hashlib.sha256(raw).hexdigest(),size=len(raw),truncated=req.truncated,ciphertext=f.encrypt(raw))
        db.add(row)
        record(db,"llm.content",Principal(kind="user",user_id=s.user_id,device_id=s.device_id),source=p.user_id,session_id=s.id,
               data={"content_id":row.id,"request_id":row.request_id,"direction":row.direction,"sha256":row.sha256,"size":row.size,"truncated":row.truncated})
        db.commit()
        return {"content_id":row.id,"sha256":row.sha256}

@app.get("/v1/audit/content")
def list_content(session_id:str|None=None,request_id:str|None=None,p:Principal=Depends(require("admin"))):
    """Content metadata (no bodies) for one session or request."""
    if not session_id and not request_id: raise HTTPException(422,"give session_id or request_id")
    with Session() as db:
        q=select(LlmContent).order_by(LlmContent.created_at)
        if session_id: q=q.where(LlmContent.session_id==session_id)
        if request_id: q=q.where(LlmContent.request_id==request_id)
        return {"contents":[{"content_id":r.id,"session_id":r.session_id,"request_id":r.request_id,"direction":r.direction,"sha256":r.sha256,
                             "size":r.size,"truncated":r.truncated,"created_at":utc(r.created_at).isoformat()} for r in db.scalars(q.limit(1000))]}

@app.get("/v1/audit/content/{content_id}")
def read_content(content_id:str,reason:str=Query(min_length=1,max_length=500),p:Principal=Depends(require("admin"))):
    """Decrypt one body for an investigation. Every read is audited with the reader and the reason."""
    f=content_cipher()
    with Session() as db:
        row=db.get(LlmContent,content_id)
        # Purged content is gone, like content that never existed: 404 either way. The llm.content
        # event (id, hash, size) and the audit.content.purge event remain.
        if not row: raise HTTPException(404,"content not found (it may have been purged after the retention period)")
        try: text=f.decrypt(row.ciphertext).decode()
        except InvalidToken: raise HTTPException(500,"content cannot be decrypted with the configured key")
        record(db,"audit.content.read",p,source="policy-api",session_id=row.session_id,message=reason,
               data={"content_id":row.id,"request_id":row.request_id,"direction":row.direction,"reason":reason})
        db.commit()
        return {"content_id":row.id,"session_id":row.session_id,"request_id":row.request_id,"direction":row.direction,
                "sha256":row.sha256,"truncated":row.truncated,"content":text}

# --- content retention and legal hold (ADR 0001, D5) -------------------------------

HOLD_SCOPES=("user","session","job")
# Who purges when no administrator does: the CronJob CLI and the in-process loop.
RETENTION_ACTOR=Principal(kind="service",user_id="content-retention")
log=logging.getLogger("policy-api")

def int_env(name,default,minimum):
    raw=env(name,default).strip() or default
    try: v=int(raw)
    except ValueError: raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if v<minimum: raise ValueError(f"{name} must be at least {minimum}, got {v}")
    return v

def content_retention_days():
    """Days prompt/response bodies are kept (default 90). Values below 1 are a misconfiguration and
    raise instead of being clamped or defaulted: 0 would destroy every body at the next purge, and
    silently falling back to 90 would hide a setting that legal/privacy asked for."""
    return int_env("CONTENT_RETENTION_DAYS","90",1)

def content_purge_interval():
    """Seconds between in-process purges; 0 (the default) leaves purging to the CronJob."""
    return int_env("CONTENT_PURGE_INTERVAL_SECONDS","0",0)

class HoldReq(BaseModel):
    scope:str=Field(pattern="^(user|session|job)$"); value:str=Field(min_length=1,max_length=256); reason:str=Field(min_length=1,max_length=500)

def hold_view(h):
    return {"id":h.id,"scope":h.scope,"value":h.value,"reason":h.reason,"created_by":h.created_by,"created_at":utc(h.created_at).isoformat(),
            "released_by":h.released_by,"released_at":utc(h.released_at).isoformat() if h.released_at else None}

def held():
    """SQL condition: this llm_contents row is under an open hold. It is part of the DELETE itself,
    so a hold committed before the statement runs wins even over a purge that already picked the row."""
    is_open=ContentHold.released_at.is_(None)
    by_session=exists().where(is_open,ContentHold.scope=="session",ContentHold.value==LlmContent.session_id).correlate(LlmContent)
    by_owner=exists().where(is_open,AgentSession.id==LlmContent.session_id,or_(
        and_(ContentHold.scope=="user",ContentHold.value==AgentSession.user_id),
        and_(ContentHold.scope=="job",ContentHold.value==AgentSession.job_id))).correlate(LlmContent)
    return or_(by_session,by_owner)

def purge_contents(actor,*,trigger,dry_run=False,at=None,batch_size=None):
    """Delete bodies older than CONTENT_RETENTION_DAYS that no open hold covers, in batches.

    Age is compared in Python with utc(), not in SQL: SQLite stores timestamps as naive strings and
    such comparisons were unreliable here before. Rows are scanned by primary key (keyset), metadata
    columns only. Idempotent and safe to run concurrently: each batch deletes by id with the hold
    check in the same statement, so a row is deleted once and counted by the run that deleted it.
    Emits exactly one audit.content.purge event with counts only, also when the run fails."""
    days=content_retention_days(); batch=batch_size or int_env("CONTENT_PURGE_BATCH_SIZE","500",1)
    cutoff=(at or now())-timedelta(days=days)
    # expired: past the cutoff; held: of those, under an open hold at scan time; deleted: by this run.
    stats={"expired":0,"held":0,"deleted":0,"open_holds":0}; error=None
    try:
        with Session() as db:
            holds={(h.scope,h.value) for h in db.scalars(select(ContentHold).where(ContentHold.released_at.is_(None)))}
            stats["open_holds"]=len(holds); last=""
            while True:
                rows=db.execute(select(LlmContent.id,LlmContent.session_id,LlmContent.created_at,AgentSession.user_id,AgentSession.job_id)
                                .outerjoin(AgentSession,AgentSession.id==LlmContent.session_id)
                                .where(LlmContent.id>last).order_by(LlmContent.id).limit(batch)).all()
                if not rows: break
                last=rows[-1].id; doomed=[]
                for r in rows:
                    if utc(r.created_at)>=cutoff: continue
                    stats["expired"]+=1
                    if {("session",r.session_id),("user",r.user_id),("job",r.job_id)}&holds: stats["held"]+=1
                    else: doomed.append(r.id)
                if doomed and not dry_run:
                    res=db.execute(delete(LlmContent).where(LlmContent.id.in_(doomed),~held()).execution_options(synchronize_session=False))
                    stats["deleted"]+=res.rowcount; db.commit()
    except Exception as e:
        error=e; raise
    finally:
        # Expired, not held at scan time, and not deleted here: removed by a concurrent purge or held meanwhile.
        stats["skipped_other"]=0 if dry_run else stats["expired"]-stats["held"]-stats["deleted"]
        out={"trigger":trigger,"dry_run":dry_run,"retention_days":days,"cutoff":cutoff.isoformat(),**stats}
        if dry_run: out["would_delete"]=stats["expired"]-stats["held"]
        if error is not None: out["error"]=type(error).__name__
        with Session() as db:
            record(db,"audit.content.purge",actor,source="policy-api",success=error is None,
                   message=f"{'dry run: ' if dry_run else ''}{out.get('would_delete',stats['deleted'])} content bodies past {days} days",data=out)
            db.commit()
    return out

async def purge_loop(interval):
    while True:
        try: await asyncio.to_thread(purge_contents,RETENTION_ACTOR,trigger="schedule")
        except Exception: log.exception("content purge failed")
        await asyncio.sleep(interval)

@app.post("/v1/admin/audit/content/purge")
def purge_content(dry_run:bool=False,p:Principal=Depends(require("admin"))):
    """Run the retention purge now. dry_run=true only counts. Normally run by `python -m app.purge`."""
    return purge_contents(p,trigger="api",dry_run=dry_run)

@app.post("/v1/admin/audit/content/holds")
def start_hold(req:HoldReq,p:Principal=Depends(require("admin"))):
    """Legal hold: content of this user, session or job is kept past retention until the hold is released."""
    with Session() as db:
        h=ContentHold(id=str(uuid.uuid4()),scope=req.scope,value=req.value,reason=req.reason,created_by=p.user_id,created_at=now())
        db.add(h)
        record(db,"audit.content.hold.start",p,source="policy-api",message=req.reason,data=hold_view(h))
        db.commit()
        return hold_view(h)

@app.get("/v1/admin/audit/content/holds")
def list_holds(include_released:bool=False,p:Principal=Depends(require("admin"))):
    with Session() as db:
        q=select(ContentHold).order_by(ContentHold.created_at)
        if not include_released: q=q.where(ContentHold.released_at.is_(None))
        return {"holds":[hold_view(h) for h in db.scalars(q.limit(1000))]}

@app.delete("/v1/admin/audit/content/holds/{hold_id}")
def release_hold(hold_id:str,reason:str=Query(min_length=1,max_length=500),p:Principal=Depends(require("admin"))):
    """Release a hold. Its content becomes subject to the normal retention purge again."""
    with Session() as db:
        h=db.get(ContentHold,hold_id)
        if not h or h.released_at: raise HTTPException(404,"no open hold with this id")
        h.released_at,h.released_by=now(),p.user_id
        record(db,"audit.content.hold.end",p,source="policy-api",message=reason,data={**hold_view(h),"release_reason":reason})
        db.commit()
        return hold_view(h)

# --- local-agent jobs (ADR 0001, D1) -----------------------------------------------

LOCAL_AGENT="local"
JOB_SESSION_GRACE_SECONDS=300
JOB_STATUSES=("pending","approved","rejected","disabled")

class JobReq(BaseModel):
    name:str=Field(min_length=1,max_length=128); repo:str=Field(min_length=1,max_length=1024); environment:str="development"
    model:str=Field(min_length=1,max_length=256); task:str=Field(min_length=1,max_length=20000)
    interval_minutes:int|None=None; max_runtime_seconds:int=Field(default=3600,gt=0)

class DecisionReq(BaseModel):
    reason:str=Field(min_length=1,max_length=500)

def job_view(j):
    iso=lambda d: utc(d).isoformat() if d else None
    return {"id":j.id,"name":j.name,"owner":j.owner,"repo":j.repo,"environment":j.environment,"model":j.model,"task":j.task,
            "interval_minutes":j.interval_minutes,"max_runtime_seconds":j.max_runtime_seconds,"status":j.status,
            "requested_at":iso(j.requested_at),"decided_by":j.decided_by,"decided_at":iso(j.decided_at),"decision_reason":j.decision_reason,
            "last_scheduled_at":iso(j.last_scheduled_at)}

def job_is_due(j,at):
    return bool(j.interval_minutes) and (j.last_scheduled_at is None or utc(j.last_scheduled_at)+timedelta(minutes=j.interval_minutes)<=at)

def job_session_principal(db,req):
    """Who a job session belongs to, and whether this run may start at all."""
    if not req.job_id: raise HTTPException(403,"local agents run only as administrator-approved jobs")
    job=db.get(AgentJob,req.job_id)
    if not job: raise HTTPException(404,"job not found")
    if job.status!="approved": raise HTTPException(403,f"job is {job.status}, not approved")
    tokens=db.scalars(select(SessionToken).join(AgentSession,AgentSession.id==SessionToken.session_id).where(AgentSession.job_id==job.id))
    if any(utc(t.expires_at)>now() for t in tokens): raise HTTPException(409,"this job is already running")
    if req.trigger=="manual":
        user,groups=verify_user_token(req.user_token)
        p=Principal(kind="user",user_id=user,groups=groups,device_id=req.device_id,device_verified=req.device_verified)
        if user!=job.owner and not is_admin(p): raise HTTPException(403,"only the job owner or an administrator can run this job")
        return job,p
    if req.trigger=="schedule":
        # The schedule is enforced here, not by the orchestrator: stolen orchestrator credentials
        # cannot run a job more often than it was approved for.
        if not job.interval_minutes: raise HTTPException(403,"job has no schedule")
        if not job_is_due(job,now()): raise HTTPException(409,"job is not due yet")
        return job,Principal(kind="user",user_id=f"job:{job.id}",device_id="scheduler")
    raise HTTPException(422,"job sessions need trigger manual or schedule")

@app.post("/v1/agent/jobs")
def request_job(req:JobReq,p:Principal=Depends(require("user"))):
    """Ask for a local-agent job. It stays pending until an administrator other than the requester approves it."""
    if req.environment not in bundles.ENVIRONMENTS: raise HTTPException(422,f"unknown environment {req.environment!r}")
    if req.environment=="production": raise HTTPException(422,"agents do not run against production")
    min_interval=int(env("AGENT_JOB_MIN_INTERVAL_MINUTES","15")); max_runtime=int(env("AGENT_JOB_MAX_RUNTIME_SECONDS","14400"))
    if req.interval_minutes is not None and req.interval_minutes<min_interval: raise HTTPException(422,f"interval_minutes must be at least {min_interval}")
    if req.max_runtime_seconds>max_runtime: raise HTTPException(422,f"max_runtime_seconds must be at most {max_runtime}")
    # Jobs run against a remote repository the orchestrator clones, never a local path.
    if bundles.normalize_repo(req.repo).startswith("local:"): raise HTTPException(422,"repo must be a remote repository URL")
    with Session() as db:
        j=AgentJob(id=str(uuid.uuid4()),owner=p.user_id,status="pending",requested_at=now(),**req.model_dump())
        db.add(j)
        record(db,"agent.job.request",p,source="policy-api",message=req.name,data={k:v for k,v in job_view(j).items() if k!="task"}|{"task_sha256":hashlib.sha256(req.task.encode()).hexdigest()})
        db.commit()
        return job_view(j)

@app.get("/v1/agent/jobs")
def list_jobs(status:str|None=None,p:Principal=Depends(require("user"))):
    """Your own jobs; administrators see every job."""
    with Session() as db:
        q=select(AgentJob).order_by(AgentJob.requested_at.desc())
        if not is_admin(p): q=q.where(AgentJob.owner==p.user_id)
        if status: q=q.where(AgentJob.status==status)
        return {"jobs":[job_view(j) for j in db.scalars(q.limit(500))]}

@app.get("/v1/agent/jobs/due")
def due_jobs(p:Principal=Depends(require("service",service="sandbox-orchestrator"))):
    """Approved, scheduled jobs whose interval has passed. The Policy API re-checks at session creation."""
    with Session() as db:
        at=now()
        return {"jobs":[{"id":j.id,"name":j.name} for j in db.scalars(select(AgentJob).where(AgentJob.status=="approved",AgentJob.interval_minutes.is_not(None))) if job_is_due(j,at)]}

def decide(job_id,to,allowed_from,event,reason,p):
    with Session() as db:
        j=db.get(AgentJob,job_id)
        if not j: raise HTTPException(404,"job not found")
        if j.status not in allowed_from: raise HTTPException(409,f"job is {j.status}")
        # Separation of duties: nobody approves their own job.
        if to=="approved" and j.owner==p.user_id: raise HTTPException(403,"a job must be approved by an administrator other than its owner")
        j.status,j.decided_by,j.decided_at,j.decision_reason=to,p.user_id,now(),reason
        record(db,event,p,source="policy-api",message=reason,data={"job_id":j.id,"name":j.name,"owner":j.owner,"status":to,"reason":reason,
                                                                   "task_sha256":hashlib.sha256(j.task.encode()).hexdigest()})
        db.commit()
        return job_view(j)

@app.post("/v1/admin/agent/jobs/{job_id}/approve")
def approve_job(job_id:str,req:DecisionReq,p:Principal=Depends(require("admin"))):
    return decide(job_id,"approved",("pending",),"agent.job.approve",req.reason,p)

@app.post("/v1/admin/agent/jobs/{job_id}/reject")
def reject_job(job_id:str,req:DecisionReq,p:Principal=Depends(require("admin"))):
    return decide(job_id,"rejected",("pending",),"agent.job.reject",req.reason,p)

@app.post("/v1/admin/agent/jobs/{job_id}/disable")
def disable_job(job_id:str,req:DecisionReq,p:Principal=Depends(require("admin"))):
    """Stop future runs. A run in progress is stopped with the kill switch (revoke by job_id)."""
    return decide(job_id,"disabled",("pending","approved"),"agent.job.disable",req.reason,p)

@app.post("/v1/agent/sessions/{session_id}/end")
def end_session(session_id:str,p:Principal=Depends(require("service",service="sandbox-orchestrator"))):
    """The orchestrator ends a job session when its run is over, so the token dies with the sandbox."""
    with Session() as db:
        s=db.get(AgentSession,session_id); t=db.get(SessionToken,session_id)
        if not s or not t or not s.job_id: raise HTTPException(404,"no job session with this id")
        if utc(t.expires_at)>now():
            t.expires_at=now()
            record(db,"session.end",Principal(kind="user",user_id=s.user_id,device_id=s.device_id),source="sandbox-orchestrator",session_id=s.id,
                   data={"job_id":s.job_id,"trigger":s.trigger})
        db.commit()
        return {"ended":session_id}

# --- guardrail break-glass (ADR 0001, D4) -------------------------------------------

BYPASS_SCOPES=("all","policy","user","session","model")

class BypassReq(BaseModel):
    scope:str=Field(pattern="^(all|policy|user|session|model)$"); target:str|None=Field(default=None,max_length=256)
    reason:str=Field(min_length=1,max_length=500); ttl_seconds:int=Field(gt=0)

def bypass_view(b):
    return {"id":b.id,"scope":b.scope,"target":b.target,"reason":b.reason,"created_by":b.created_by,
            "created_at":utc(b.created_at).isoformat(),"expires_at":utc(b.expires_at).isoformat()}

def open_bypasses(db):
    """Bypasses still in force. Ones past their expiry are closed here, with an audit event."""
    out=[]
    for b in db.scalars(select(GuardrailBypass).where(GuardrailBypass.ended_at.is_(None))):
        if utc(b.expires_at)<=now():
            b.ended_at,b.ended_by=b.expires_at,"expired"
            record(db,"guardrail.bypass.end",Principal(kind="service",user_id="policy-api"),source="policy-api",message="expired",
                   data={**bypass_view(b),"ended_by":"expired"})
        else: out.append(b)
    return out

def bypass_applies(b,s,pol):
    # Model-scoped bypasses are returned for every session; the gateway applies them per request model.
    return b.scope in ("all","model") or (b.scope,b.target) in {("policy",pol.id),("user",s.user_id),("session",s.id)}

@app.post("/v1/admin/guardrails/bypass")
def start_bypass(req:BypassReq,p:Principal=Depends(require("admin"))):
    """Lift guardrails for a scope until the TTL ends. Everything else (session checks, model
    allow-lists, network policy, content audit) stays in force. Takes effect at the LLM gateway
    within its session cache time (15 s); expiry is enforced there exactly."""
    limit=int(env("GUARDRAIL_BYPASS_MAX_SECONDS","14400"))
    if req.ttl_seconds>limit: raise HTTPException(422,f"ttl_seconds must be at most {limit}")
    if (req.scope=="all")!=(req.target is None): raise HTTPException(422,"target is required for every scope except all, and not allowed for all")
    with Session() as db:
        b=GuardrailBypass(id=str(uuid.uuid4()),scope=req.scope,target=req.target,reason=req.reason,created_by=p.user_id,
                          created_at=now(),expires_at=now()+timedelta(seconds=req.ttl_seconds))
        db.add(b)
        record(db,"guardrail.bypass.start",p,source="policy-api",message=req.reason,data=bypass_view(b))
        db.commit()
        return bypass_view(b)

@app.get("/v1/admin/guardrails/bypass")
def list_bypasses(p:Principal=Depends(require("admin","service",service="siem"))):
    with Session() as db:
        out=[bypass_view(b) for b in open_bypasses(db)]
        db.commit()
        return {"bypasses":out}

@app.delete("/v1/admin/guardrails/bypass/{bypass_id}")
def end_bypass(bypass_id:str,reason:str=Query(min_length=1,max_length=500),p:Principal=Depends(require("admin"))):
    with Session() as db:
        b=db.get(GuardrailBypass,bypass_id)
        if not b or b.ended_at: raise HTTPException(404,"no open bypass with this id")
        b.ended_at,b.ended_by=now(),p.user_id
        record(db,"guardrail.bypass.end",p,source="policy-api",message=reason,data={**bypass_view(b),"ended_by":p.user_id,"end_reason":reason})
        db.commit()
        return {"ended":bypass_id}

# --- OpenShell gateway interceptor -------------------------------------------------

@app.get("/v1/sandboxes/{name}/authorization")
def sandbox_authorization(name:str,p:Principal=Depends(require("service",service="gateway-interceptor"))):
    """What the gateway may let exist under this sandbox name: the compiled policy and provider
    set of the newest active session that was issued it. Anything else is refused at the gateway,
    so even stolen orchestrator credentials cannot create or widen a sandbox."""
    with Session() as db:
        q=select(AgentSession,SessionToken).join(SessionToken,SessionToken.session_id==AgentSession.id)\
            .where(AgentSession.sandbox_name==name).order_by(AgentSession.created_at.desc())
        for s,t in db.execute(q):
            if utc(t.expires_at)<=now(): continue
            pol=pinned_policy(db,s)
            if not pol: continue
            compiled=compile_policy(pol.document,WORKSPACE,platform())
            return {"authorized":True,"sandbox_name":name,"session_id":s.id,"user_id":s.user_id,"policy_id":pol.id,"policy_version":pol.version,
                    "policy_hash":s.policy_hash,"openshell_policy":compiled,"providers":sandbox_providers(name,pol.document),"expires_at":utc(t.expires_at).isoformat()}
    raise HTTPException(404,"no active session was issued this sandbox")
