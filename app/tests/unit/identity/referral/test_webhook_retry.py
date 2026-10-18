"""Tenant webhooks retry transient failures so rewards are not silently lost."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from apps.identity.referral import services as referral

URL = "https://example.com/hook"


def _script(
    monkeypatch: pytest.MonkeyPatch, statuses: list[object]
) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    async def handle(  # ruff:ignore[unused-async]
        self: object, request: httpx.Request
    ) -> httpx.Response:
        seen.append(request)
        outcome = statuses[len(seen) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(int(outcome), json={}, request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    return seen


async def _post() -> None:
    with (
        patch.object(referral, "validate_public_url", new=AsyncMock()),
        patch.object(referral.asyncio, "sleep", new=AsyncMock()) as sleep,
    ):
        await referral._post_webhook(url=URL, headers=None, payload={"a": 1})
    _post.sleeps = [c.args[0] for c in sleep.await_args_list]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_retries_server_errors_until_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _script(monkeypatch, [503, 502, 200])

    await _post()

    assert len(seen) == 3
    assert len(_post.sleeps) == 2  # type: ignore[attr-defined]
    assert _post.sleeps[0] < _post.sleeps[1]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_retries_connection_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _script(monkeypatch, [httpx.ConnectError("down"), 204])

    await _post()

    assert len(seen) == 2


@pytest.mark.asyncio
async def test_does_not_retry_client_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _script(monkeypatch, [403, 200])

    await _post()

    assert len(seen) == 1


@pytest.mark.asyncio
async def test_gives_up_after_the_last_attempt_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _script(monkeypatch, [500] * 10)

    await _post()

    assert len(seen) == referral.WEBHOOK_ATTEMPTS
