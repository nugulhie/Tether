"""Versioned policies from signed bundles; policy hash on sessions.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    # Keep every (id, version) instead of overwriting one row per policy id.
    with op.batch_alter_table("policies", recreate="always") as b:
        b.alter_column("enabled", new_column_name="active", existing_type=sa.Boolean)
        b.add_column(sa.Column("priority", sa.Integer, nullable=False, server_default="0"))
        b.add_column(sa.Column("match", sa.JSON, nullable=True))
        b.add_column(sa.Column("bundle_serial", sa.Integer, nullable=True))
        b.create_primary_key("policies_pkey", ["id", "version"])
    # Rows seeded by the code default (not from a signed bundle) must not be selectable.
    op.execute("UPDATE policies SET active = false WHERE bundle_serial IS NULL")
    op.create_table("policy_bundles",
        sa.Column("serial", sa.Integer, primary_key=True, autoincrement=False),
        sa.Column("git_commit", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("signed", sa.Boolean, nullable=False),
        sa.Column("key_id", sa.String(128), nullable=True),
        sa.Column("loaded_at", sa.DateTime(timezone=True)))
    op.add_column("agent_sessions", sa.Column("policy_hash", sa.String(64), nullable=True))


def downgrade():
    op.drop_column("agent_sessions", "policy_hash")
    op.drop_table("policy_bundles")
    op.execute("DELETE FROM policies WHERE bundle_serial IS NOT NULL AND (id, version) NOT IN (SELECT id, MAX(version) FROM policies GROUP BY id)")
    with op.batch_alter_table("policies", recreate="always") as b:
        b.drop_constraint("policies_pkey", type_="primary")
        b.create_primary_key("policies_pkey", ["id"])
        b.drop_column("bundle_serial")
        b.drop_column("match")
        b.drop_column("priority")
        b.alter_column("active", new_column_name="enabled", existing_type=sa.Boolean)
