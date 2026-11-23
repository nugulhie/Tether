import os

from alembic import context
from sqlalchemy import create_engine

from app.models import Base

target_metadata = Base.metadata


def run(connection):
    # render_as_batch lets the same migrations alter tables on SQLite (tests).
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if connection is not None:
    run(connection)
else:
    with create_engine(os.environ["DATABASE_URL"]).begin() as conn:
        run(conn)
