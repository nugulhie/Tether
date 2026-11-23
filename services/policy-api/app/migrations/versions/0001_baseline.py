"""Baseline: schema as created by Base.metadata.create_all before Alembic.

Tables that already exist are left alone, so databases created by earlier versions
(with or without session_tokens) upgrade cleanly.

Revision ID: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "policies" not in existing:
        op.create_table("policies",
            sa.Column("id", sa.String(128), primary_key=True),
            sa.Column("version", sa.Integer, nullable=False),
            sa.Column("document", sa.JSON, nullable=False),
            sa.Column("enabled", sa.Boolean))
    if "agent_sessions" not in existing:
        op.create_table("agent_sessions",
            sa.Column("id", sa.String(128), primary_key=True),
            sa.Column("user_id", sa.String(128)),
            sa.Column("device_id", sa.String(128)),
            sa.Column("agent", sa.String(64)),
            sa.Column("repo", sa.String(1024)),
            sa.Column("environment", sa.String(64)),
            sa.Column("policy_id", sa.String(128)),
            sa.Column("policy_version", sa.Integer),
            sa.Column("sandbox_name", sa.String(128)),
            sa.Column("created_at", sa.DateTime(timezone=True)))
    if "session_tokens" not in existing:
        op.create_table("session_tokens",
            sa.Column("session_id", sa.String(128), primary_key=True),
            sa.Column("token_hash", sa.String(64)),
            sa.Column("device_verified", sa.Boolean),
            sa.Column("expires_at", sa.DateTime(timezone=True)))
        op.create_index("ix_session_tokens_token_hash", "session_tokens", ["token_hash"], unique=True)
    if "audit_events" not in existing:
        op.create_table("audit_events",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("event_type", sa.String(128)),
            sa.Column("payload", sa.JSON),
            sa.Column("created_at", sa.DateTime(timezone=True)))


def downgrade():
    for t in ("audit_events", "session_tokens", "agent_sessions", "policies"):
        op.drop_table(t)
