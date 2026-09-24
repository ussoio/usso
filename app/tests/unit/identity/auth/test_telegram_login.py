"""Unit tests for Telegram OIDC login helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from apps.identity.auth.enums import AuthIdentifier, AuthSecret
from apps.identity.auth.services.oauth import resolve_oauth_identity
from apps.identity.auth.services.telegram import (
    TELEGRAM_OIDC_DISCOVERY_URL,
    TELEGRAM_OIDC_ISSUER,
    build_telegram_login_request,
    ensure_telegram_discovery,
    require_telegram_oauth,
    telegram_display_name,
    telegram_user_id_from_claims,
    verify_telegram_id_token,
)
from apps.tenant.secrets import OAuthSecret
from server.exceptions import BadRequestError, UnauthorizedError


def test_require_telegram_oauth_missing() -> None:
    """Missing oauth_secrets.telegram raises BadRequestError."""
    tenant = MagicMock()
    tenant.secrets.oauth_secrets = {}
    with pytest.raises(BadRequestError) as exc:
        require_telegram_oauth(tenant)
    assert exc.value.error_code == "telegram_not_configured"


def test_ensure_telegram_discovery_default() -> None:
    """Empty discovery URL is filled with Telegram OIDC discovery."""
    secret = OAuthSecret(client_id="1", client_secret="s")
    filled = ensure_telegram_discovery(secret)
    assert filled.discovery_url == TELEGRAM_OIDC_DISCOVERY_URL


def test_telegram_user_id_and_display_name() -> None:
    """Claims map to telegram id and display name."""
    claims = {
        "id": 987654321,
        "given_name": "Ada",
        "family_name": "Lovelace",
        "preferred_username": "ada",
    }
    assert telegram_user_id_from_claims(claims) == "987654321"
    assert telegram_display_name(claims) == "Ada Lovelace"
    assert telegram_display_name({"name": "Full Name"}) == "Full Name"


def test_telegram_user_id_missing_openid_only_points_to_botfather_alg() -> None:
    """Openid-only tokens usually mean EdDSA/ES256K in BotFather Advanced."""
    with pytest.raises(UnauthorizedError) as exc:
        telegram_user_id_from_claims({
            "aud": "1",
            "exp": 1,
            "iat": 1,
            "iss": "https://oauth.telegram.org",
            "nonce": "n",
            "sub": "1234123412341234123",
        })
    assert exc.value.error_code == "telegram_auth_invalid"
    assert "RS256" in str(exc.value.detail)
    assert "RS256" in exc.value.message["en"]
    assert "RS256" in exc.value.message["fa"]


def test_telegram_user_id_missing() -> None:
    """Missing id claim is rejected when sub is not a telegram id."""
    with pytest.raises(UnauthorizedError) as exc:
        telegram_user_id_from_claims({"sub": "x", "name": "Ada"})
    assert exc.value.error_code == "telegram_auth_invalid"
    assert "keys=" in str(exc.value.detail)


def test_telegram_user_id_accepts_numeric_sub_fallback() -> None:
    """Numeric sub that validates as telegram_id is accepted without id."""
    assert telegram_user_id_from_claims({"sub": "47719525"}) == "47719525"


def test_oidc_audience_matches_int_or_str() -> None:
    from apps.identity.auth.services.telegram import oidc_audience_matches

    assert oidc_audience_matches(8716247878, "8716247878") is True
    assert oidc_audience_matches("8716247878", "8716247878") is True
    assert oidc_audience_matches(["8716247878"], "8716247878") is True
    assert oidc_audience_matches(1, "8716247878") is False


def test_build_telegram_login_request() -> None:
    """LoginRequest uses telegram_id + telegram_token."""
    login = build_telegram_login_request(
        telegram_user_id="987654321",
        id_token="id.jwt.token",
    )
    assert login.type == AuthIdentifier.TELEGRAM_ID
    assert login.identifier == "987654321"
    assert login.method == AuthSecret.TELEGRAM_TOKEN
    assert login.secret == "id.jwt.token"


def test_resolve_oauth_identity_telegram() -> None:
    """Telegram provider resolves to TELEGRAM_ID identity."""
    identity = resolve_oauth_identity(
        provider="telegram",
        userinfo={"id": 987654321, "name": "Ada"},
    )
    assert identity.identifier_type == AuthIdentifier.TELEGRAM_ID
    assert identity.identifier == "987654321"
    assert identity.method == AuthSecret.TELEGRAM_TOKEN
    assert identity.name == "Ada"


def test_resolve_oauth_identity_email_provider() -> None:
    """Non-Telegram providers require email."""
    identity = resolve_oauth_identity(
        provider="google",
        userinfo={"email": "a@b.co", "email_verified": True, "name": "A"},
    )
    assert identity.identifier_type == AuthIdentifier.EMAIL
    assert identity.method == AuthSecret.OAUTH

    with pytest.raises(BadRequestError) as exc:
        resolve_oauth_identity(provider="google", userinfo={"name": "A"})
    assert exc.value.error_code == "oauth_email_missing"

    with pytest.raises(BadRequestError) as exc:
        resolve_oauth_identity(
            provider="google",
            userinfo={"email": "a@b.co", "email_verified": False},
        )
    assert exc.value.error_code == "oauth_email_unverified"


def test_verify_telegram_id_token_success() -> None:
    """Successful JWT verify returns claims including id."""
    fake_jwt = MagicMock()
    fake_jwt.verify.return_value = True
    fake_jwt.payload = {
        "iss": TELEGRAM_OIDC_ISSUER,
        "aud": "123",
        "id": 987654321,
        "name": "Ada",
    }
    fake_jwt.unverified_payload = fake_jwt.payload
    with patch(
        "apps.identity.auth.services.telegram.JWT",
        return_value=fake_jwt,
    ) as jwt_cls:
        claims = verify_telegram_id_token(
            id_token="tok",
            client_id="123",
            jwks_uri="https://oauth.telegram.org/.well-known/jwks.json",
        )
    assert claims["id"] == 987654321
    jwt_cls.assert_called_once()
    cfg = jwt_cls.call_args.kwargs["config"]
    assert cfg.issuer == TELEGRAM_OIDC_ISSUER
    assert cfg.audience is None


def test_verify_telegram_id_token_failure() -> None:
    """Failed JWT verify raises telegram_auth_invalid."""
    fake_jwt = MagicMock()
    fake_jwt.verify.side_effect = Exception("bad sig")
    with (
        patch(
            "apps.identity.auth.services.telegram.JWT",
            return_value=fake_jwt,
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        verify_telegram_id_token(
            id_token="tok",
            client_id="123",
            jwks_uri="https://oauth.telegram.org/.well-known/jwks.json",
        )
    assert exc.value.error_code == "telegram_auth_invalid"


def test_require_telegram_oauth_configured() -> None:
    """Configured Telegram secret is returned as-is."""
    secret = OAuthSecret(client_id="1", client_secret="s")
    tenant = MagicMock()
    tenant.secrets.oauth_secrets = {"telegram": secret}
    assert require_telegram_oauth(tenant) is secret


def test_ensure_telegram_discovery_keeps_existing_url() -> None:
    """Existing discovery URL is not overwritten."""
    secret = OAuthSecret(
        client_id="1",
        client_secret="s",
        discovery_url="https://example.test/.well-known/openid",
    )
    assert ensure_telegram_discovery(secret) is secret


def test_telegram_display_name_username_fallback() -> None:
    """preferred_username is used when name/given/family are absent."""
    assert telegram_display_name({"preferred_username": "ada"}) == "ada"
    assert telegram_display_name({}) is None


def test_oidc_audience_matches_rejects_empty_or_bool() -> None:
    from apps.identity.auth.services.telegram import oidc_audience_matches

    assert oidc_audience_matches("1", "") is False
    assert oidc_audience_matches(True, "1") is False
    assert oidc_audience_matches(None, "1") is False


def test_verify_telegram_id_token_rejects_unverified_or_bad_aud() -> None:
    """False verify result and audience mismatch raise UnauthorizedError."""
    fake_jwt = MagicMock()
    fake_jwt.verify.return_value = False
    with (
        patch(
            "apps.identity.auth.services.telegram.JWT",
            return_value=fake_jwt,
        ),
        pytest.raises(UnauthorizedError) as unverified,
    ):
        verify_telegram_id_token(
            id_token="tok",
            client_id="123",
            jwks_uri="https://oauth.telegram.org/.well-known/jwks.json",
        )
    assert unverified.value.error_code == "telegram_auth_invalid"

    fake_jwt.verify.return_value = True
    fake_jwt.unverified_payload = {"aud": "other", "id": 1}
    with (
        patch(
            "apps.identity.auth.services.telegram.JWT",
            return_value=fake_jwt,
        ),
        pytest.raises(UnauthorizedError) as aud,
    ):
        verify_telegram_id_token(
            id_token="tok",
            client_id="123",
            jwks_uri="https://oauth.telegram.org/.well-known/jwks.json",
        )
    assert aud.value.error_code == "telegram_auth_invalid"
    assert "audience" in str(aud.value.detail)
