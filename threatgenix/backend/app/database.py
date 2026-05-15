import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# Normalize DB URL for asyncpg (postgres:// or postgresql:// → postgresql+asyncpg://)
_db_url = settings.database_url
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

# Strip ?sslmode= from URL — asyncpg takes ssl as a connect_arg, not a query param
_ssl_mode: str | None = None
if "sslmode=" in _db_url:
    import re as _re
    _match = _re.search(r"[?&]sslmode=([^&]+)", _db_url)
    if _match:
        _ssl_mode = _match.group(1)
    _db_url = _re.sub(r"[?&]sslmode=[^&]*", "", _db_url).rstrip("?")

# DATABASE_SSL env var overrides URL-derived ssl mode (set to "require" for Supabase)
_ssl_env = os.getenv("DATABASE_SSL", "").lower()
if _ssl_env in {"require", "true", "1"}:
    _ssl_mode = "require"

_connect_args: dict = {}
if _ssl_mode == "require":
    _connect_args["ssl"] = "require"

engine = create_async_engine(_db_url, echo=False, connect_args=_connect_args)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
