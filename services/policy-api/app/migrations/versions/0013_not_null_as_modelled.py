"""NOT NULL where the models say so. Early migrations left these columns nullable; the application always
sets them, so the database now enforces it too. Found by app.schema_check on Postgres (release gate).

Rows from before Alembic (P0 databases) can still hold NULLs there. They are filled first with values that
read as "unknown" and can never be mistaken for real data: "unknown" ids, version 0, an empty token hash
(no token hashes to it), and the migration time for missing timestamps (a token without an expiry thus
counts as expired). Nothing is deleted.

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

COLUMNS = {
    "agent_sessions": ["user_id", "device_id", "agent", "repo", "environment", "policy_id", "policy_version", "sandbox_name", "created_at"],
    "audit_events": ["event_type", "payload", "created_at"],
    "policies": ["active"],
    "policy_bundles": ["loaded_at"],
    "session_tokens": ["token_hash", "device_verified", "expires_at"],
}


UNKNOWN = {"user_id": "unknown", "device_id": "unknown", "agent": "unknown", "repo": "unknown", "environment": "unknown",
           "policy_id": "unknown", "policy_version": 0, "sandbox_name": "unknown", "event_type": "unknown",
           "active": False, "token_hash": "", "device_verified": False}


def _backfill():
    for table, columns in COLUMNS.items():
        for c in columns:
            if c in ("created_at", "loaded_at", "expires_at"):
                value = sa.func.current_timestamp()
            elif c == "payload":
                value = sa.literal_column("'{}'")  # an untyped literal: Postgres casts it to json, a bound varchar it would not
            else:
                value = sa.literal(UNKNOWN[c])
            op.execute(sa.table(table, sa.column(c)).update().where(sa.column(c).is_(None)).values({c: value}))


def _set(nullable):
    for table, columns in COLUMNS.items():
        with op.batch_alter_table(table) as t:
            for c in columns:
                t.alter_column(c, nullable=nullable)


def upgrade():
    _backfill()
    _set(False)


def downgrade():
    _set(True)
