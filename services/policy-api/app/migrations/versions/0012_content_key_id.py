"""Content key ids: each stored body records which key encrypted it, so the key can be rotated.

Existing rows were encrypted with CONTENT_ENCRYPTION_KEY, which the keyring reads as "default".

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("llm_contents") as t:
        t.add_column(sa.Column("key_id", sa.String(32), nullable=False, server_default="default"))
    op.create_index("ix_llm_contents_key_id", "llm_contents", ["key_id"])


def downgrade():
    # Only safe while every row is still on "default": rows on other keys would become unreadable
    # to a version that knows a single key.
    op.drop_index("ix_llm_contents_key_id", "llm_contents")
    with op.batch_alter_table("llm_contents") as t:
        t.drop_column("key_id")
