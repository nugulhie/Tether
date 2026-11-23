"""Network filter state in endpoint heartbeats.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("device_status", sa.Column("filter_running", sa.Boolean, nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("device_status", "filter_running")
