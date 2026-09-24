"""Unit tests for rate limiter initialization."""

from unittest.mock import MagicMock, patch

import pytest

from server import rate_limiter


@pytest.mark.asyncio
async def test_init_rate_limiter_memory_fallback() -> None:
    """Without Redis, limiters are created in-memory."""
    rate_limiter._limiters.clear()
    with patch.object(rate_limiter, "redis_client", None):
        await rate_limiter.init_rate_limiter()
    assert rate_limiter._limiters
    # Re-init should reuse existing configs
    before = dict(rate_limiter._limiters)
    with patch.object(rate_limiter, "redis_client", None):
        await rate_limiter.init_rate_limiter()
    assert rate_limiter._limiters.keys() == before.keys()


@pytest.mark.asyncio
async def test_reset_rate_limiters() -> None:
    """Reset clears and rebuilds limiters."""
    rate_limiter._limiters.clear()
    with patch.object(rate_limiter, "redis_client", None):
        await rate_limiter.init_rate_limiter()
        assert rate_limiter._limiters
        await rate_limiter.reset_rate_limiters()
    assert rate_limiter._limiters


def test_generate_fingerprint_ignores_header() -> None:
    """A caller-controlled fingerprint header is never trusted."""
    request = MagicMock()
    request.headers = {"X-Fingerprint": "explicit-fp"}
    request.cookies = {}
    request.client = MagicMock(host="127.0.0.1")
    request.url = MagicMock(hostname="sso.example.test")
    assert rate_limiter.generate_fingerprint(request) != "explicit-fp"


def test_generate_fingerprint_from_request_parts() -> None:
    """Fingerprint falls back to hashing host/IP/UA."""
    request = MagicMock()
    request.headers = {"User-Agent": "pytest-agent-" + ("x" * 40)}
    request.cookies = {}
    request.client = MagicMock(host="127.0.0.1")
    request.url = MagicMock(hostname="sso.example.test")
    fp = rate_limiter.generate_fingerprint(request)
    assert isinstance(fp, str) and len(fp) == 64


@pytest.mark.asyncio
async def test_get_identifier_factory() -> None:
    """Identifier factory returns an async callable."""
    request = MagicMock()
    request.headers = {"User-Agent": "pytest", "authorization": "Bearer x"}
    request.cookies = {}
    request.client = MagicMock(host="127.0.0.1")
    request.url = MagicMock(hostname="sso.example.test")
    identify = rate_limiter.get_identifier("/auth/login", auth_required=False)
    value = await identify(request)
    assert isinstance(value, str) and value
