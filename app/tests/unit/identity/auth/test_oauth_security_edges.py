"""Security edge coverage for external OIDC providers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.auth.services import oauth
from apps.tenant.secrets import OAuthSecret
from server.exceptions import BadRequestError
from utils.outbound import UnsafeOutboundURLError


@pytest.mark.asyncio
async def test_oidc_endpoint_requires_safe_nonempty_url() -> None:
    with pytest.raises(BadRequestError) as missing:
        await oauth._validated_oidc_endpoint({}, "token_endpoint")
    assert missing.value.error_code == "invalid_oidc_configuration"

    with (
        patch.object(
            oauth,
            "validate_public_url",
            new=AsyncMock(side_effect=UnsafeOutboundURLError("private")),
        ),
        pytest.raises(BadRequestError) as unsafe,
    ):
        await oauth._validated_oidc_endpoint(
            {"token_endpoint": "https://127.0.0.1/token"},
            "token_endpoint",
        )
    assert unsafe.value.error_code == "unsafe_oidc_endpoint"

    with patch.object(
        oauth,
        "validate_public_url",
        new=AsyncMock(return_value="https://provider.example/token"),
    ):
        assert (
            await oauth._validated_oidc_endpoint(
                {"token_endpoint": "https://provider.example/token"},
                "token_endpoint",
            )
            == "https://provider.example/token"
        )


@pytest.mark.asyncio
async def test_fetch_oidc_config_validates_before_request() -> None:
    response = MagicMock()
    response.json.return_value = {"issuer": "https://provider.example"}
    client = AsyncMock()
    client.__aenter__.return_value.get = AsyncMock(return_value=response)
    with (
        patch.object(oauth, "validate_public_url", new=AsyncMock()),
        patch.object(oauth.httpx, "AsyncClient", return_value=client),
    ):
        result = await oauth.fetch_oidc_config.__wrapped__(
            "https://provider.example/.well-known/openid-configuration"
        )
    assert result["issuer"] == "https://provider.example"
    response.raise_for_status.assert_called_once()


def test_safe_oauth_profile_filters_privileged_and_unsafe_claims() -> None:
    long_name = "x" * 300
    profile = oauth._safe_oauth_profile_data(
        provider="example",
        userinfo={
            "given_name": long_name,
            "family_name": "User",
            "picture": "https://cdn.example/avatar.png",
            "sub": "subject",
            "name": "Display",
            "locale": "fa",
            "roles": ["admin"],
            "is_admin": True,
        },
    )
    assert profile["first_name"] == long_name[:256]
    assert profile["last_name"] == "User"
    assert profile["avatar_url"] == "https://cdn.example/avatar.png"
    assert "roles" not in profile
    assert "is_admin" not in profile

    unsafe = oauth._safe_oauth_profile_data(
        provider="example",
        userinfo={"picture": "https://user:pass@cdn.example/avatar.png"},
    )
    assert "avatar_url" not in unsafe


def test_provider_resolution_errors_and_custom_telegram_discovery() -> None:
    tenant = SimpleNamespace(secrets=SimpleNamespace(oauth_secrets={}))
    with pytest.raises(BadRequestError) as missing:
        oauth.resolve_provider_secret(tenant, "missing")
    assert missing.value.error_code == "provider_not_configured"

    secret = OAuthSecret(
        client_id="id",
        client_secret="secret",
        discovery_url="https://custom.example/.well-known/openid-configuration",
        scopes=["custom"],
    )
    tenant.secrets.oauth_secrets["telegram"] = secret
    with patch.object(
        oauth, "ensure_telegram_discovery", return_value=secret
    ) as ensure:
        resolved = oauth.resolve_provider_secret(tenant, "telegram")
    ensure.assert_called_once_with(secret)
    assert resolved.scopes == ["openid", "custom", "profile"]
    assert resolved.client_id == "id"
