"""Guardrail break-glass (ADR 0001, D4): time-limited, scoped, audited bypasses.

Revision ID: 0007
Revises: 0006
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("guardrail_bypasses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("target", sa.String(256), nullable=True),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        # Reserved for two-person approval; a single administrator may bypass for now.
        sa.Column("approved_by", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_by", sa.String(128), nullable=True))
    op.create_index("ix_guardrail_bypasses_open", "guardrail_bypasses", ["ended_at"])


def downgrade():
    op.drop_table("guardrail_bypasses")
