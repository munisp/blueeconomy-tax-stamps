"""Redis-backed nonce replay guard + rate limiting. FAIL-CLOSED: any Redis
outage raises RedisUnavailable and the API answers 503; verification never
fails open."""

from __future__ import annotations

import time

import redis.asyncio as aioredis

from taxstamps.config import Settings


class RedisUnavailable(RuntimeError):
    pass


_client: aioredis.Redis | None = None


def init_redis(settings: Settings) -> aioredis.Redis | None:
    global _client
    if not settings.redis_configured:
        _client = None
        return None
    _client = aioredis.from_url(  # type: ignore[no-untyped-call]
        settings.redis_url, socket_timeout=2.0, socket_connect_timeout=2.0
    )
    return _client


def get_redis() -> aioredis.Redis:
    if _client is None:
        raise RedisUnavailable("redis not configured")
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None


async def ping() -> bool:
    try:
        return bool(await get_redis().ping())
    except Exception:
        return False


async def claim_nonce(key: str, ttl_seconds: int = 300) -> None:
    """Single-use nonce: raises RedisUnavailable on outage, ValueError on replay."""
    try:
        ok = await get_redis().set(key, "1", nx=True, ex=ttl_seconds)
    except RedisUnavailable:
        raise
    except Exception as exc:
        raise RedisUnavailable(str(exc)) from exc
    if not ok:
        raise ValueError("nonce replay")


async def rate_limit(bucket: str, limit_per_minute: int) -> None:
    """Fixed-window rate limit. Raises ValueError when exceeded, RedisUnavailable on outage."""
    window = int(time.time()) // 60
    key = f"taxstamps:rl:{bucket}:{window}"
    try:
        client = get_redis()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, 90)
    except RedisUnavailable:
        raise
    except Exception as exc:
        raise RedisUnavailable(str(exc)) from exc
    if count > limit_per_minute:
        raise ValueError("rate limit exceeded")
