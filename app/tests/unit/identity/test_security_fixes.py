"""Unit tests for security fixes: API key OAuth path and agent response."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.agent.schemas import AgentResponseSchema
from apps.identity.api_key.services import enforce_api_key_ip_whitelist
from server.exceptions import ForbiddenError


def test_agent_response_schema_excludes_hashed_secret() -> None:
    """Public agent responses must not expose hashed_client_secret."""
    fields = AgentResponseSchema.model_fields
    assert "hashed_client_secret" not in fields
    assert "kid" in fields


@pytest.mark.asyncio
async def test_oauth_client_credentials_enforces_api_key_ip() -> None:
    """client_credentials path applies the same IP allowlist as verify."""
    from apps.tenant.integration import services as oauth_services
    from utils.request_context import client_ip_var, user_agent_var

    api_key = MagicMock(
        uid="key-1",
        scopes=["read:x"],
        workspace_id=None,
        user_id="u1",
        created_by="u1",
        ip_whitelist=["1.2.3.4"],
        rate_limit={},
        hashed_client_secret="hash",
    )
    tenant = MagicMock(uid="t1")
    ip_token = client_ip_var.set("9.9.9.9")
    ua_token = user_agent_var.set("test")

    try:
        with (
            patch(
                "apps.identity.api_key.models.APIKey.find_one",
                new=AsyncMock(return_value=api_key),
            ),
            patch(
                "apps.identity.api_key.services.verify_client_secret",
                return_value=True,
            ),
            patch(
                "apps.identity.api_key.services._validate_api_key_state",
            ),
            pytest.raises(ForbiddenError) as exc,
        ):
            await oauth_services.exchange_service_account_client_credentials(
                tenant=tenant,
                client_id="key-1",
                client_secret="secret",
                scope=None,
            )
        assert exc.value.error_code == "api_key_ip_denied"
    finally:
        client_ip_var.reset(ip_token)
        user_agent_var.reset(ua_token)


def test_enforce_api_key_ip_whitelist_allows_listed() -> None:
    """Listed IPs pass the allowlist check."""
    key = MagicMock(ip_whitelist=["1.2.3.4"])
    enforce_api_key_ip_whitelist(key, client_ip="1.2.3.4")
