"""Unit tests for OAuth session creation and code exchange."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.auth.services.oauth import (
    create_oauth_session,
    exchange_oauth_code_for_userinfo,
)
from server.exceptions import BadRequestError


def _tenant_with_provider() -> MagicMock:
    tenant = MagicMock()
    tenant.primary_url = "https://sso.example.test"
    tenant.primary_domain = "sso.example.test"
    secrets = MagicMock()
    secrets.discovery_url = "https://idp.example.test/.well-known/openid-configuration"
    secrets.client_id = "client-id"
    secrets.client_secret = "client-secret"
    secrets.scopes = ["openid", "email"]
    tenant.secrets.oauth_secrets = {"google": secrets}
    return tenant


@pytest.mark.asyncio
async def test_create_oauth_session_requires_provider() -> None:
    """Missing provider configuration raises BadRequestError."""
    tenant = MagicMock()
    tenant.secrets.oauth_secrets = {}
    with pytest.raises(BadRequestError) as exc:
        await create_oauth_session(tenant=tenant, provider="google")
    assert exc.value.error_code == "provider_not_configured"


@pytest.mark.asyncio
async def test_create_oauth_session_builds_authorization_url() -> None:
    """Authorization URL includes client_id, state, and redirect_uri."""
    tenant = _tenant_with_provider()
    with (
        patch(
            "apps.identity.auth.services.oauth.fetch_oidc_config",
            new_callable=AsyncMock,
            return_value={"authorization_endpoint": "https://idp.example.test/auth"},
        ),
        patch(
            "apps.identity.auth.services.oauth.generate_oauth_redirect_uri",
            return_value="https://sso.example.test/callback",
        ),
        patch(
            "apps.identity.auth.services.oauth.validate_public_url",
            new_callable=AsyncMock,
        ),
    ):
        url_state = await create_oauth_session(tenant=tenant, provider="google")
    assert url_state.state
    assert "client_id=client-id" in url_state.authorization_url
    assert "https://idp.example.test/auth?" in url_state.authorization_url
    assert "redirect_uri=" in url_state.authorization_url


@pytest.mark.asyncio
async def test_exchange_oauth_code_for_userinfo() -> None:
    """Code exchange posts to token endpoint and returns id_token payload."""
    tenant = _tenant_with_provider()
    token_json = {"id_token": "id.jwt.token"}
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = token_json

    client = AsyncMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    jwt_obj = MagicMock()
    jwt_obj.payload = {
        "email": "u@example.test",
        "sub": "oidc-1",
        "nonce": "expected-nonce",
        "aud": "client-id",
    }
    jwt_obj.unverified_payload = jwt_obj.payload
    jwt_obj.verify = MagicMock(return_value=True)

    with (
        patch(
            "apps.identity.auth.services.oauth.fetch_oidc_config",
            new_callable=AsyncMock,
            return_value={
                "token_endpoint": "https://idp.example.test/token",
                "jwks_uri": "https://idp.example.test/jwks",
                "issuer": "https://idp.example.test",
            },
        ),
        patch(
            "apps.identity.auth.services.oauth.generate_oauth_redirect_uri",
            return_value="https://sso.example.test/callback",
        ),
        patch(
            "apps.identity.auth.services.oauth.httpx.AsyncClient",
            return_value=client,
        ),
        patch(
            "apps.identity.auth.services.oauth.validate_public_url",
            new_callable=AsyncMock,
        ),
        patch("apps.identity.auth.services.oauth.JWT", return_value=jwt_obj),
    ):
        id_token, userinfo, jwks = await exchange_oauth_code_for_userinfo(
            code="auth-code",
            tenant=tenant,
            provider="google",
            expected_nonce="expected-nonce",
        )
    assert id_token == "id.jwt.token"
    assert userinfo["email"] == "u@example.test"
    assert jwks.endswith("/jwks")
