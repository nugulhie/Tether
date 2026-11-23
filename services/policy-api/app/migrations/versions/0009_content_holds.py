"""Content retention (ADR 0001, D5): legal holds that exempt prompt/response content from the
CONTENT_RETENTION_DAYS purge.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("content_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("value", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_by", sa.String(128), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_content_holds_open", "content_holds", ["released_at"])


def downgrade():
    op.drop_table("content_holds")
