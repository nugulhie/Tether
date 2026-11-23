"""Endpoint agent heartbeats for tamper detection.

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("device_status",
        sa.Column("device_id", sa.String(128), primary_key=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_version", sa.String(32), nullable=False),
        sa.Column("rules_sha256", sa.String(64), nullable=False),
        sa.Column("es_running", sa.Boolean, nullable=False),
        sa.Column("sip_enabled", sa.Boolean, nullable=False),
        sa.Column("healthy", sa.Boolean, nullable=False),
        sa.Column("denied_total", sa.Integer, nullable=False, server_default="0"))


def downgrade():
    op.drop_table("device_status")
