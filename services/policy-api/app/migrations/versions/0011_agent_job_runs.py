"""Job run results: what a local-agent run produced, for its owner to read after the sandbox is gone.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("agent_job_runs",
        sa.Column("session_id", sa.String(128), primary_key=True),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("returncode", sa.Integer, nullable=True),
        sa.Column("timed_out", sa.Boolean, nullable=False),
        sa.Column("error", sa.String(1000), nullable=True),
        sa.Column("output_content_id", sa.String(36), nullable=True),
        sa.Column("output_truncated", sa.Boolean, nullable=False),
        sa.Column("log_content_id", sa.String(36), nullable=True),
        sa.Column("diff_content_id", sa.String(36), nullable=True),
        sa.Column("diff_truncated", sa.Boolean, nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_agent_job_runs_job_id", "agent_job_runs", ["job_id"])


def downgrade():
    op.drop_table("agent_job_runs")
