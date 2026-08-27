from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

import evoruntime.db.models  # noqa: F401  # registers ORM models on Base.metadata
from evoruntime.db.base import Base
from evoruntime.db.settings import get_database_settings

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
#
# `disable_existing_loggers=False` is load-bearing rather than cosmetic:
# the default (True) disables every logger already created in the process,
# which includes `evoruntime.audit`. Any process that runs a migration
# in-process — a startup hook, a management script, a test session — would
# afterwards emit no holdout denial records at all, and the failure is
# silent because logging never raises.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# alembic.ini deliberately leaves sqlalchemy.url unset. If the caller (a
# script, a test, `-x` override) already set one on this Config object, it
# wins; otherwise fall back to DatabaseSettings (EVORUNTIME_DATABASE_URL) so
# the application and migrations agree on where they connect by default.
config.set_main_option(
    "sqlalchemy.url",
    config.get_main_option("sqlalchemy.url") or get_database_settings().database_url,
)

# Domain models register themselves on Base.metadata via evoruntime.db.models,
# imported above; autogenerate diffs against this single metadata object.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
