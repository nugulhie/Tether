"""Prompt and response bodies from the LLM gateway (ADR 0001, D5): every model request and
response is kept, encrypted, and linked to its llm.request event by request_id.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("llm_contents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("truncated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_llm_contents_session_id", "llm_contents", ["session_id"])
    op.create_index("ix_llm_contents_request_id", "llm_contents", ["request_id"])


def downgrade():
    op.drop_table("llm_contents")
