import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg://agent:agent@localhost:5432/agent_security"), pool_pre_ping=True)
Session = sessionmaker(bind=engine)


def alembic_config(connection=None):
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


def migrate(bind=None):
    with (bind or engine).begin() as conn:
        command.upgrade(alembic_config(conn), "head")
