from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Policy(Base):
    # Every published (id, version) is kept; `active` marks the versions in the
    # latest bundle. Sessions pin the exact version they started with.
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    match: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    bundle_serial: Mapped[int | None] = mapped_column(Integer, nullable=True)


class PolicyBundle(Base):
    __tablename__ = "policy_bundles"
    serial: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    git_commit: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64))
    signed: Mapped[bool] = mapped_column(Boolean)
    key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AgentSession(Base):
    __tablename__ = "agent_sessions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(128))
    device_id: Mapped[str] = mapped_column(String(128))
    agent: Mapped[str] = mapped_column(String(64))
    repo: Mapped[str] = mapped_column(String(1024))
    environment: Mapped[str] = mapped_column(String(64))
    policy_id: Mapped[str] = mapped_column(String(128))
    policy_version: Mapped[int] = mapped_column(Integer)
    policy_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sandbox_name: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Local-agent job sessions (ADR 0001, D1): which approved job, started by a person or the schedule.
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    trigger: Mapped[str | None] = mapped_column(String(16), nullable=True)
    triggered_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class SessionToken(Base):
    __tablename__ = "session_tokens"
    session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    device_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    # Hash chain (app/audit_chain.py); NULL for events written before migration 0010.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)



class LlmContent(Base):
    # Prompt and response bodies relayed by the LLM gateway, encrypted at rest (Fernet,
    # CONTENT_ENCRYPTION_KEY). Audit events carry only the id and hash; reading the body is
    # an administrator action that is itself audited.
    __tablename__ = "llm_contents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    direction: Mapped[str] = mapped_column(String(16))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ContentHold(Base):
    # Legal hold on prompt/response content: while open (released_at is NULL), content in its
    # scope is never purged, whatever its age. scope is user | session | job; value is the
    # user id, session id or job id. Holds are released, never deleted.
    __tablename__ = "content_holds"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    released_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GuardrailBypass(Base):
    # Break-glass (ADR 0001, D4): an administrator lifts guardrails for a scope until expires_at.
    # Session checks, model allow-lists, network policy and content audit stay in force.
    __tablename__ = "guardrail_bypasses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16))
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(128))
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class AgentJob(Base):
    # A local-LLM agent task an administrator approved (ADR 0001, D1). Jobs are immutable once
    # requested: a change is a new job and a new approval. Runs are started by the owner (or an
    # administrator) or by the schedule, never more often than interval_minutes.
    __tablename__ = "agent_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    owner: Mapped[str] = mapped_column(String(128), index=True)
    repo: Mapped[str] = mapped_column(String(1024))
    environment: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(256))
    task: Mapped[str] = mapped_column(Text)
    interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_runtime_seconds: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | approved | rejected | disabled
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
