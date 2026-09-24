"""
Database and cache initialization.

This module wires the application to Redis through
``fastapi_mongo_base.db.redis`` so that fatal Redis errors (connection
failures, script-cache loss such as ``NoScriptError``) trigger the
library's force-exit guard and the process restarts cleanly.
"""

from __future__ import annotations

from fastapi_mongo_base import db as fmb_db
from fastapi_mongo_base.db.redis import close_redis as fmb_close_redis

from server.config import Settings


def _redis_guarded_available() -> bool:
    """Whether fastapi-mongo-base's guarded Redis init can be used."""
    return callable(getattr(fmb_db, "init_redis", None))


def init_redis(
    settings: object | None = None,
) -> tuple[object | None, object | None]:
    """
    Initialize Redis connections (sync and async) via fastapi-mongo-base.

    Connects through ``fastapi_mongo_base.db.redis.init_redis``, whose
    guard proxy force-exits the process on fatal Redis errors.
    """
    if not _redis_guarded_available():
        raise ImportError(
            "fastapi-mongo-base is required for guarded Redis connections. "
            "Install with: pip install 'fastapi-mongo-base[redis]'"
        )

    return fmb_db.init_redis(settings)


def _unwrap_guarded(client: object | None) -> object | None:
    """Return the underlying raw Redis client if wrapped by the guard."""
    if client is None:
        return None
    return getattr(client, "_client", client)


async def close_redis(
    sync_client: object | None = None,
    async_client: object | None = None,
) -> None:
    """
    Close Redis clients if supported.

    ``fastapi_mongo_base`` wraps clients in guard proxies that do not
    expose ``close``/``aclose``; unwrap to the underlying raw client
    before closing.
    """
    sync_raw = _unwrap_guarded(sync_client)
    async_raw = _unwrap_guarded(async_client)
    await fmb_close_redis(sync_raw, async_raw)


# Module-level clients: the async client is the shared handle used across
# the application (rate limiting, captcha, QR login, queues, caches).
# Pass Settings() so REDIS_URI from the environment (including testcontainers)
# is visible; init_redis(None) never reads it.
redis_sync, redis_async = init_redis(Settings())
if redis_async is None:
    raise ValueError("Redis is not initialized")
redis: object = redis_async
