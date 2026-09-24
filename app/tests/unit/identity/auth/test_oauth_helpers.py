"""Unit tests for OAuth helper functions."""

from unittest.mock import MagicMock

import pytest
from starlette.datastructures import URL

from apps.identity.auth.services.oauth import (
    build_url_with_params,
    generate_oauth_redirect_uri,
    sanitize_return_url,
)
from server.config import Settings


def test_build_url_with_params_merges_query() -> None:
    """Existing query params are preserved and updated."""
    url = build_url_with_params(
        "https://example.test/path?a=1",
        {"b": "2", "a": "9"},
    )
    assert "a=9" in url
    assert "b=2" in url
    assert url.startswith("https://example.test/path?")


def test_generate_oauth_redirect_uri() -> None:
    """Callback URI uses tenant URL and provider name."""
    tenant = MagicMock()
    tenant.primary_url = "https://sso.example.test"
    tenant.domains = ["sso.example.test"]
    uri = generate_oauth_redirect_uri(tenant, "google")
    assert uri.endswith(f"{Settings.base_path}/auth/oauth/google/callback")
    assert uri.startswith("https://")


@pytest.mark.parametrize(
    ("return_url", "expected"),
    [
        (None, None),
        ("", None),
        ("https://evil.test/x", None),
        ("//evil.test/x", None),
        ("/\\evil.test/x", None),
        ("javascript:alert(1)", None),
        ("http://app.example.test/home", None),
        ("https://app.example.test/home", "https://app.example.test/home"),
        ("dashboard", "/dashboard"),
        ("/relative", "/relative"),
    ],
)
def test_sanitize_return_url(return_url: str | None, expected: str | None) -> None:
    """Return URLs must match tenant domains or be relative paths."""
    tenant = MagicMock()
    tenant.domains = ["app.example.test"]
    tenant.primary_domain = "sso.example.test"
    tenant.config.allowed_return_domains = []
    assert sanitize_return_url(return_url, tenant) == expected


def test_sanitize_return_url_allows_configured_extra_domain() -> None:
    """allowed_return_domains expands the allowlist."""
    tenant = MagicMock()
    tenant.domains = []
    tenant.primary_domain = "sso.example.test"
    tenant.config.allowed_return_domains = ["partner.example.test"]
    assert (
        sanitize_return_url("https://partner.example.test/cb", tenant)
        == "https://partner.example.test/cb"
    )
    assert isinstance(URL("https://partner.example.test/cb"), URL)


@pytest.mark.asyncio
async def test_create_oauth_session_returns_oauth_session_type() -> None:
    """create_oauth_session returns OAuthSession with URL and state."""
    from unittest.mock import AsyncMock, patch

    from apps.identity.auth.services.oauth import OAuthSession, create_oauth_session
    from apps.tenant.secrets import OAuthSecret

    tenant = MagicMock()
    tenant.primary_url = "https://sso.example.test"
    tenant.domains = ["sso.example.test"]
    tenant.secrets.oauth_secrets = {
        "google": OAuthSecret(
            discovery_url=(
                "https://accounts.google.com/.well-known/openid-configuration"
            ),
            client_id="cid",
            client_secret="sec",
            scopes=["openid", "email"],
        )
    }

    with patch(
        "apps.identity.auth.services.oauth.fetch_oidc_config",
        new_callable=AsyncMock,
        return_value={
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        },
    ):
        session = await create_oauth_session(tenant=tenant, provider="google")

    assert isinstance(session, OAuthSession)
    assert "client_id=cid" in session.authorization_url
    assert session.state
    assert session.code_verifier is None


@pytest.mark.asyncio
async def test_create_oauth_session_telegram_uses_pkce() -> None:
    """Telegram OIDC authorize request includes PKCE challenge."""
    from unittest.mock import AsyncMock, patch

    from apps.identity.auth.services.oauth import create_oauth_session
    from apps.tenant.secrets import OAuthSecret

    tenant = MagicMock()
    tenant.primary_url = "https://sso.example.test"
    tenant.domains = ["sso.example.test"]
    tenant.secrets.oauth_secrets = {
        "telegram": OAuthSecret(
            client_id="42",
            client_secret="sec",
        )
    }

    with patch(
        "apps.identity.auth.services.oauth.fetch_oidc_config",
        new_callable=AsyncMock,
        return_value={
            "authorization_endpoint": "https://oauth.telegram.org/auth",
            "token_endpoint": "https://oauth.telegram.org/token",
            "jwks_uri": "https://oauth.telegram.org/.well-known/jwks.json",
        },
    ):
        session = await create_oauth_session(tenant=tenant, provider="telegram")

    assert session.code_verifier
    assert "code_challenge=" in session.authorization_url
    assert "code_challenge_method=S256" in session.authorization_url
    assert "scope=openid+profile" in session.authorization_url or (
        "scope=openid%20profile" in session.authorization_url
    )
