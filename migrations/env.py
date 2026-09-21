from __future__ import annotations

from logging.config import fileConfig

from alembic import context

from agentguard_api import models  # noqa: F401
from agentguard_api.config import get_settings
from agentguard_api.database import Base, create_database_engine

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
config.set_main_option("sqlalchemy.url", get_settings().database_url.replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata,
        literal_binds=True, dialect_opts={"paramstyle": "named"}, compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # This resolves DATABASE_HOST/USER/AUTH and managed-identity tokens in Azure,
    # while continuing to use DATABASE_URL for local development.
    connectable = create_database_engine()
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
