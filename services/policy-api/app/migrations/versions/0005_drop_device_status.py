"""Remove endpoint-agent heartbeats (the macOS endpoint extension was dropped: it needs Apple
entitlements the company cannot obtain). Laptop controls are now MDM-delivered Claude Code
managed settings and a DNS profile, which report nothing to the Policy API.

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table("device_status")


def downgrade():
    op.create_table("device_status",
        sa.Column("device_id", sa.String(128), primary_key=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_version", sa.String(32), nullable=False),
        sa.Column("rules_sha256", sa.String(64), nullable=False),
        sa.Column("es_running", sa.Boolean, nullable=False),
        sa.Column("sip_enabled", sa.Boolean, nullable=False),
        sa.Column("healthy", sa.Boolean, nullable=False),
        sa.Column("denied_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("filter_running", sa.Boolean, nullable=False, server_default=sa.false()))
