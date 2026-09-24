"""Additional branch coverage for Redis and path rate limiting."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server import rate_limiter
from utils.net import get_client_ip

_REAL_RATE_LIMIT_CALL = rate_limiter.PathRateLimiter.__call__


@pytest.mark.asyncio
async def test_init_rate_limiter_uses_redis_bucket() -> None:
    rate_limiter._limiters.clear()
    bucket = MagicMock()
    with (
        patch.object(rate_limiter, "MAX_REQUESTS", {"default": 30}),
        patch.object(rate_limiter, "redis_client", object()),
        patch.object(
            rate_limiter.RedisBucket, "init", new=AsyncMock(return_value=bucket)
        ) as init,
    ):
        await rate_limiter.init_rate_limiter()
    init.assert_awaited_once()
    assert (30, 60) in rate_limiter._limiters


@pytest.mark.asyncio
async def test_init_rate_limiter_falls_back_when_redis_fails() -> None:
    rate_limiter._limiters.clear()
    with (
        patch.object(rate_limiter, "MAX_REQUESTS", {"default": 30}),
        patch.object(rate_limiter, "redis_client", object()),
        patch.object(
            rate_limiter.RedisBucket,
            "init",
            new=AsyncMock(side_effect=RuntimeError("redis down")),
        ),
        patch.object(rate_limiter.logger, "exception") as log,
    ):
        await rate_limiter.init_rate_limiter()
    assert (30, 60) in rate_limiter._limiters
    log.assert_called_once()


def test_generate_fingerprint_ignores_client_controlled_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace(
        headers={"X-Fingerprint": "header-fp"},
        cookies={"usso_fingerprint": "cookie-fp"},
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(hostname="sso.test"),
    )
    fingerprint = rate_limiter.generate_fingerprint(request)
    assert fingerprint not in {"header-fp", "cookie-fp"}

    monkeypatch.setenv("TRUSTED_PROXY_NETWORKS", "127.0.0.0/8")
    request = SimpleNamespace(
        headers={"X-Forwarded-For": "203.0.113.4, 10.0.0.1", "User-Agent": "agent"},
        cookies={},
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(hostname="sso.test"),
    )
    forwarded = rate_limiter.generate_fingerprint(request)
    request.headers["X-Forwarded-For"] = "198.51.100.2"
    assert rate_limiter.generate_fingerprint(request) != forwarded


def test_client_ip_ignores_spoofed_leftmost_forwarded_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_NETWORKS", "127.0.0.0/8")
    request = SimpleNamespace(
        headers={"X-Forwarded-For": "198.51.100.8, 203.0.113.9"},
        client=SimpleNamespace(host="127.0.0.1"),
    )
    assert get_client_ip(request) == "203.0.113.9"


def test_client_ip_walks_multiple_trusted_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRUSTED_PROXY_NETWORKS", "127.0.0.0/8,10.0.0.0/8")
    request = SimpleNamespace(
        headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.2"},
        client=SimpleNamespace(host="127.0.0.1"),
    )
    assert get_client_ip(request) == "203.0.113.9"


@pytest.mark.asyncio
async def test_authenticated_identifier_includes_authenticated_marker() -> None:
    request = SimpleNamespace(
        state=SimpleNamespace(user_id="user-1"),
        headers={"X-Fingerprint": "fp"},
        cookies={},
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(hostname="sso.test"),
    )
    identify = rate_limiter.get_identifier("/private", auth_required=True)
    assert await identify(request) == (
        f"/private:user-1:{rate_limiter.generate_fingerprint(request)}"
    )


def test_path_limiter_resolves_and_caches_missing_limiter() -> None:
    limiter = rate_limiter.PathRateLimiter(
        path="/test", auth_required=False, max_requests=2, time_window=60
    )
    rate_limiter._limiters.pop((2, 60), None)
    resolved = limiter._resolve_limiter()
    assert rate_limiter._limiters[2, 60] is resolved
    assert limiter._resolve_limiter() is resolved


@pytest.mark.asyncio
@pytest.mark.parametrize("success", [True, False])
async def test_path_limiter_calls_callback_only_when_rejected(success: bool) -> None:
    dependency = rate_limiter.PathRateLimiter(
        path="/test", auth_required=False, max_requests=2, time_window=60
    )
    acquired = SimpleNamespace(try_acquire_async=AsyncMock(return_value=success))
    dependency.callback = AsyncMock(return_value=None)
    request = SimpleNamespace(
        state=SimpleNamespace(user_id=None),
        headers={"X-Fingerprint": "fp"},
        cookies={},
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(hostname="sso.test"),
    )
    response = MagicMock()
    with patch.object(dependency, "_resolve_limiter", return_value=acquired):
        assert await _REAL_RATE_LIMIT_CALL(dependency, request, response) is None
    acquired.try_acquire_async.assert_awaited_once_with(
        f"/test:-:{rate_limiter.generate_fingerprint(request)}", blocking=False
    )
    assert dependency.callback.await_count == (0 if success else 1)


def test_get_rate_limiter_uses_normalized_fractional_configuration() -> None:
    dependency = rate_limiter.get_rate_limiter(
        "/auth/request-magic-link", auth_required=True
    )
    assert dependency._config == (1, 600)
