"""Tamper evidence for the audit log: each event stores the hash of the previous one.

Existing rows keep NULL hashes; the chain starts at the first event written after this migration.

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("audit_events") as b:
        b.add_column(sa.Column("prev_hash", sa.String(64), nullable=True))
        b.add_column(sa.Column("hash", sa.String(64), nullable=True))


def downgrade():
    with op.batch_alter_table("audit_events") as b:
        b.drop_column("hash")
        b.drop_column("prev_hash")
