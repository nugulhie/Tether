"""Local-LLM agent jobs (ADR 0001, D1): administrator-approved tasks run by a person or a
schedule, and the job/trigger of each session they start.

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("agent_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("repo", sa.String(1024), nullable=False),
        sa.Column("environment", sa.String(64), nullable=False),
        sa.Column("model", sa.String(256), nullable=False),
        sa.Column("task", sa.Text, nullable=False),
        sa.Column("interval_minutes", sa.Integer, nullable=True),
        sa.Column("max_runtime_seconds", sa.Integer, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(500), nullable=True),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_agent_jobs_owner", "agent_jobs", ["owner"])
    with op.batch_alter_table("agent_sessions") as t:
        t.add_column(sa.Column("job_id", sa.String(36), nullable=True))
        t.add_column(sa.Column("trigger", sa.String(16), nullable=True))
        t.add_column(sa.Column("triggered_by", sa.String(128), nullable=True))
    op.create_index("ix_agent_sessions_job_id", "agent_sessions", ["job_id"])


def downgrade():
    op.drop_index("ix_agent_sessions_job_id", "agent_sessions")
    with op.batch_alter_table("agent_sessions") as t:
        t.drop_column("triggered_by")
        t.drop_column("trigger")
        t.drop_column("job_id")
    op.drop_table("agent_jobs")
