"""Release gate for the database schema (ADR 0002, A-6): run against an EMPTY database.

    DATABASE_URL=postgresql+psycopg://... python -m app.schema_check

1. upgrade to head;
2. the migrated schema must match the models (app.models): a column added to a model without a
   migration, or the other way round, fails here instead of at a customer's upgrade;
3. downgrade to base and upgrade to head again: every migration can be rolled back and replayed.

Unit tests run the migrations on SQLite; customers run Postgres, so CI runs this on Postgres.
Exit status: 0 consistent, 1 drift or a failing step. Destroys the schema it creates: never point it
at a database with data in it (it refuses a database that already has tables).
"""
import os
import sys

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from .db import alembic_config
from .models import Base


def drift(conn):
    mc = MigrationContext.configure(conn, opts={"compare_type": True, "compare_server_default": False})
    return compare_metadata(mc, Base.metadata)


def main():
    engine = create_engine(os.environ["DATABASE_URL"])
    with engine.connect() as conn:
        if inspect(conn).get_table_names():
            print("refusing: the database is not empty (this check drops everything it creates)", file=sys.stderr)
            return 1
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
    with engine.connect() as conn:
        diffs = drift(conn)
    if diffs:
        print("schema drift between app/models.py and the migrations:")
        for d in diffs:
            print(f"  {d}")
        return 1
    print("upgrade head: schema matches the models")
    with engine.begin() as conn:
        command.downgrade(alembic_config(conn), "base")
    with engine.connect() as conn:
        left = [t for t in inspect(conn).get_table_names() if t != "alembic_version"]
    if left:
        print(f"downgrade base left tables behind: {left}")
        return 1
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
    print("downgrade base and upgrade head again: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
