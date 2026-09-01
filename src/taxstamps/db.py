"""Database engine/session plumbing (SQLAlchemy 2.0 async, asyncpg driver)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value < 0:
        raise RuntimeError(f"{name} must be non-negative, got {value}")
    return value


def init_engine(database_url: str) -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is not None:
        return _engine
    # Pool sizing is env-driven; defaults preserve the previous hard-coded
    # behavior (pool_size=10, max_overflow=5, pre-ping on).
    #
    #   TAXSTAMPS_DB_POOL_SIZE      steady-state connections (default 10)
    #   TAXSTAMPS_DB_MAX_OVERFLOW   burst connections above pool_size (default 5)
    #   TAXSTAMPS_DB_POOL_TIMEOUT   seconds to wait for a connection (default 30)
    #   TAXSTAMPS_DB_POOL_RECYCLE   seconds before a connection is recycled
    #                               (default 0 = disabled, unchanged)
    _engine = create_async_engine(
        database_url,
        pool_size=_env_int("TAXSTAMPS_DB_POOL_SIZE", 10),
        max_overflow=_env_int("TAXSTAMPS_DB_MAX_OVERFLOW", 5),
        pool_timeout=_env_int("TAXSTAMPS_DB_POOL_TIMEOUT", 30),
        pool_recycle=_env_int("TAXSTAMPS_DB_POOL_RECYCLE", 0) or -1,
        pool_pre_ping=True,
    )
    _sessionmaker = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("database engine not initialized")
    return _engine


@asynccontextmanager
async def session() -> AsyncIterator[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("database engine not initialized")
    async with _sessionmaker() as s:
        yield s


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
