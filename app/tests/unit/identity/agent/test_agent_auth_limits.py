"""Agent auth must not be throttled by normal traffic or log its credential."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.datastructures import Headers

from apps.identity.agent import routes
from server import rate_limiter

SECRET = "SECRET-AGENT-JWT-DO-NOT-LOG"


def test_agent_auth_limit_fits_normal_service_traffic() -> None:
    max_requests, window = rate_limiter._normalize_limit("/agents/auth")

    assert window == 60
    assert max_requests >= 300


def test_agent_scopes_shares_the_agent_auth_limit() -> None:
    limiter = rate_limiter.get_rate_limiter("/agents/auth")

    assert limiter._config == rate_limiter._normalize_limit("/agents/auth")


@pytest.mark.asyncio
async def test_agent_auth_does_not_log_the_authorization_header(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = SimpleNamespace(
        headers=Headers({
            "host": "sso.test",
            "authorization": f"Bearer {SECRET}",
            "cookie": "session=also-secret",
        })
    )
    agent = SimpleNamespace()
    payload = SimpleNamespace(scopes=["read:x"], aud="accounting")

    with (
        caplog.at_level(logging.DEBUG),
        patch.object(
            routes.AgentRouter,
            "get_tenant",
            AsyncMock(return_value=SimpleNamespace(uid="tenant-1")),
        ),
        patch.object(
            routes.services, "agent_auth", AsyncMock(return_value=(agent, payload))
        ),
        patch.object(
            routes.services, "create_agent_response", MagicMock(return_value="ok")
        ),
    ):
        result = await routes.AgentRouter().agent_auth(request)

    assert result == "ok"
    assert "sso.test" in caplog.text
    assert SECRET not in caplog.text
    assert "also-secret" not in caplog.text
