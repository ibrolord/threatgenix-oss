import asyncio
import os
from logging.config import fileConfig

from alembic import context
from alembic.script import ScriptDirectory
import sqlalchemy as sa
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.database import Base
from app.models import *  # noqa: F401, F403 — registers all models with Base.metadata
from app.seed import VECTOR_THREAT_INTEL_TABLES, repair_runtime_schema

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Allow DATABASE_URL env var to override alembic.ini (needed when running inside Docker)
_db_url = os.environ.get("DATABASE_URL")
if _db_url:
    # Normalize to asyncpg driver (postgres:// and postgresql:// → postgresql+asyncpg://)
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif _db_url.startswith("postgresql://") and "+asyncpg" not in _db_url:
        _db_url = _db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    # Strip ?sslmode= — asyncpg takes ssl as connect_arg, not URL param
    import re as _re
    _db_url = _re.sub(r"[?&]sslmode=[^&]*", "", _db_url).rstrip("?")
    config.set_main_option("sqlalchemy.url", _db_url)

target_metadata = Base.metadata
ALEMBIC_VERSION_TABLE = "alembic_version"


def _database_is_empty(connection) -> bool:
    inspector = sa.inspect(connection)
    app_tables = {
        table_name
        for table_name in inspector.get_table_names()
        if table_name != ALEMBIC_VERSION_TABLE
    }
    return not app_tables


def _enable_pgvector_if_available(connection) -> bool:
    if connection.dialect.name != "postgresql":
        return False
    try:
        available = connection.scalar(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector')")
        )
        if not available:
            return False
        connection.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
    except Exception:
        connection.rollback()
        return False
    return True


def _bootstrap_empty_database(connection) -> bool:
    """Create the current model schema when there is no historical baseline.

    The migration chain starts at revision 001, but that revision was authored
    against an already-created base schema. For a truly empty database we create
    the current SQLAlchemy schema once and stamp the active Alembic head. Existing
    databases continue through normal migrations.
    """
    if not _database_is_empty(connection):
        return False

    pgvector_enabled = _enable_pgvector_if_available(connection)
    table_names = set(Base.metadata.tables)
    if not pgvector_enabled:
        table_names -= VECTOR_THREAT_INTEL_TABLES
    tables = [table for table in Base.metadata.sorted_tables if table.name in table_names]
    Base.metadata.create_all(connection, tables=tables)
    repair_runtime_schema(connection)
    _stamp_current_heads(connection)
    connection.commit()
    return True


def _stamp_current_heads(connection) -> None:
    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()
    connection.execute(
        sa.text(
            f"CREATE TABLE IF NOT EXISTS {ALEMBIC_VERSION_TABLE} "
            "(version_num VARCHAR(32) NOT NULL)"
        )
    )
    connection.execute(sa.text(f"DELETE FROM {ALEMBIC_VERSION_TABLE}"))
    for head in heads:
        connection.execute(
            sa.text(f"INSERT INTO {ALEMBIC_VERSION_TABLE} (version_num) VALUES (:version_num)"),
            {"version_num": head},
        )


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    if _bootstrap_empty_database(connection):
        return
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    _ssl_env = os.environ.get("DATABASE_SSL", "").lower()
    _connect_args = {"ssl": "require"} if _ssl_env in {"require", "true", "1"} else {}
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=_connect_args,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
        # Explicitly commit — the async-to-sync bridge via run_sync does not
        # auto-commit, so any DDL/DML from alembic stays in an open transaction
        # until we commit here.
        await connection.commit()
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
