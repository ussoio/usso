"""Unit tests for Redis initialization helpers."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from server import db as server_db


def test_init_redis_has_no_fakeredis_fallback() -> None:
    """Redis init has no in-memory fakeredis path."""
    assert not hasattr(server_db, "_init_redis_fake")


def test_init_redis_uses_fmb_guarded_init() -> None:
    """Real Redis path delegates to fastapi-mongo-base guarded init."""
    sync_client = MagicMock(name="sync")
    async_client = MagicMock(name="async")
    with (
        patch.object(server_db, "_redis_guarded_available", return_value=True),
        patch.object(
            server_db.fmb_db, "init_redis", return_value=(sync_client, async_client)
        ) as fmb_init,
    ):
        result = server_db.init_redis(SimpleNamespace(redis_uri="redis://x"))
    fmb_init.assert_called_once()
    assert result == (sync_client, async_client)


def test_init_redis_missing_fmb_raises() -> None:
    """Without fastapi-mongo-base support, ImportError is raised."""
    with (
        patch.object(server_db, "_redis_guarded_available", return_value=False),
        pytest.raises(ImportError, match="fastapi-mongo-base"),
    ):
        server_db.init_redis(SimpleNamespace(redis_uri="redis://x"))


def test_init_redis_propagates_connection_errors() -> None:
    """Connection errors from fastapi-mongo-base propagate."""
    with (
        patch.object(server_db, "_redis_guarded_available", return_value=True),
        patch.object(
            server_db.fmb_db, "init_redis", side_effect=ConnectionError("down")
        ),
        pytest.raises(ConnectionError),
    ):
        server_db.init_redis(SimpleNamespace(redis_uri="redis://x"))


def test_unwrap_guarded_passthrough_plain_client() -> None:
    """Plain (non-guarded) clients pass through unwrapping unchanged."""
    client = MagicMock(name="plain", spec=["ping", "set"])
    assert not hasattr(client, "_client")
    assert server_db._unwrap_guarded(client) is client
    assert server_db._unwrap_guarded(None) is None


def test_unwrap_guarded_recovers_underlying_client() -> None:
    """Guard proxies expose the raw client via ``_client``."""
    raw = MagicMock(name="raw")
    guard = MagicMock(name="guard")
    guard._client = raw
    assert server_db._unwrap_guarded(guard) is raw


def test_close_redis_unwraps_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    """close_redis passes raw clients to the fastapi-mongo-base closer."""
    raw_sync = MagicMock(name="raw_sync")
    raw_async = MagicMock(name="raw_async")
    guard_sync = MagicMock(name="guard_sync")
    guard_sync._client = raw_sync
    guard_async = MagicMock(name="guard_async")
    guard_async._client = raw_async

    async def _fake_close(sync: object, async_: object) -> None:
        called.append((sync, async_))
        await asyncio.sleep(0)

    called = []
    monkeypatch.setattr(server_db, "fmb_close_redis", _fake_close)

    async def _run() -> None:
        await server_db.close_redis(guard_sync, guard_async)

    asyncio.run(_run())
    assert called == [(raw_sync, raw_async)]
