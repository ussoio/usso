"""Focused unit coverage for OAuth integration model helpers."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.tenant.integration import models
from apps.tenant.integration.schemas import TokenType


@pytest.mark.asyncio
async def test_model_lookup_helpers_build_active_unexpired_queries() -> None:
    marker = object()
    with patch.object(
        models.OAuthClient, "find_one", new=AsyncMock(return_value=marker)
    ) as find:
        assert await models.OAuthClient.get_by_client_id("client", "tenant") is marker
    assert find.await_args.args[0] == {
        "client_id": "client",
        "tenant_id": "tenant",
        "is_active": True,
    }

    with patch.object(
        models.AuthorizationCode, "find_one", new=AsyncMock(return_value=marker)
    ) as find:
        assert await models.AuthorizationCode.get_by_code("code", "tenant") is marker
    query = find.await_args.args[0]
    assert query["code"] == "code"
    assert query["expires_at"]["$gt"].tzinfo is not None

    with patch.object(
        models.OAuthToken, "find_one", new=AsyncMock(return_value=marker)
    ) as find:
        assert await models.OAuthToken.get_by_token("token", "tenant") is marker
        assert (
            await models.OAuthToken.get_by_refresh_token("refresh", "tenant") is marker
        )
    assert find.await_args_list[0].args[0]["is_revoked"] is False
    assert find.await_args_list[1].args[0]["refresh_token"] != "refresh"

    with patch.object(
        models.OAuthSession, "find_one", new=AsyncMock(return_value=marker)
    ) as find:
        assert await models.OAuthSession.get_by_state("state", "tenant") is marker
    assert find.await_args.args[0]["state"] == "state"


def test_random_value_generators_use_expected_sizes_and_prefix() -> None:
    with patch.object(
        models.secrets, "token_urlsafe", side_effect=lambda size: f"random-{size}"
    ) as token:
        assert models.OAuthClient.generate_client_id() == "uc_random-16"
        assert models.OAuthClient.generate_client_secret() == "random-32"
        assert models.AuthorizationCode.generate_code() == "random-32"
        assert models.OAuthToken.generate_token() == "random-48"
    assert [call.args[0] for call in token.call_args_list] == [16, 32, 32, 48]


def test_authorization_code_factory_and_expiry() -> None:
    def initialize(instance: object, **kwargs: object) -> None:
        instance.__dict__.update(kwargs)
        object.__setattr__(instance, "__pydantic_fields_set__", set(kwargs))
        object.__setattr__(instance, "__pydantic_extra__", None)
        object.__setattr__(instance, "__pydantic_private__", None)

    with (
        patch.object(
            models.AuthorizationCode, "generate_code", return_value="generated"
        ),
        patch.object(models.AuthorizationCode, "__init__", initialize),
    ):
        code = models.AuthorizationCode.create_code(
            client_id="client",
            user_id="user",
            tenant_id="tenant",
            redirect_uri="https://app.test/callback",
            scope=["openid"],
            nonce="nonce",
            code_challenge="challenge",
            code_challenge_method="S256",
            expires_in=30,
        )
    assert code.code == "generated"
    assert code.nonce == "nonce"
    assert code.expires_at > datetime.now(timezone.tz)
    code.expires_at = datetime.now(timezone.tz) - timedelta(seconds=1)
    assert code.is_expired() is True
    code.expires_at = datetime.now(timezone.tz) + timedelta(seconds=30)
    assert code.is_expired() is False


def test_oauth_token_factories_and_expiry() -> None:
    def initialize(instance: object, **kwargs: object) -> None:
        instance.__dict__.update(kwargs)
        object.__setattr__(instance, "__pydantic_fields_set__", set(kwargs))
        object.__setattr__(instance, "__pydantic_extra__", None)
        object.__setattr__(instance, "__pydantic_private__", None)

    with (
        patch.object(
            models.OAuthToken, "generate_token", side_effect=["access", "refresh"]
        ),
        patch.object(models.OAuthToken, "__init__", initialize),
    ):
        access = models.OAuthToken.create_access_token(
            client_id="client", user_id="user", tenant_id="tenant", scope=["openid"]
        )
        refresh = models.OAuthToken.create_refresh_token(
            client_id="client",
            user_id="user",
            tenant_id="tenant",
            scope=["openid"],
            access_token_id="access-id",
        )
    assert access.token != "access"
    assert access.raw_token == "access"
    assert access.token_type is TokenType.BEARER
    assert refresh.token == refresh.refresh_token
    assert refresh.token != "refresh"
    assert refresh.raw_token == "refresh"
    assert refresh.access_token_id == "access-id"
    access.expires_at = datetime.now(timezone.tz) - timedelta(seconds=1)
    assert access.is_expired() is True


@pytest.mark.asyncio
async def test_revoke_saves_token() -> None:
    token = models.OAuthToken.model_construct(is_revoked=False)
    with patch.object(models.OAuthToken, "save", new=AsyncMock()) as save:
        await token.revoke()
    assert token.is_revoked is True
    save.assert_awaited_once()


@pytest.mark.asyncio
async def test_revoke_related_tokens_for_access_id_and_refresh_value() -> None:
    related = SimpleNamespace(revoke=AsyncMock())
    token = models.OAuthToken.model_construct(
        access_token_id="access-id", refresh_token=None, tenant_id="tenant"
    )
    with (
        patch.object(
            models.OAuthToken, "find_one", new=AsyncMock(return_value=related)
        ) as get,
        patch.object(models.OAuthToken, "revoke", new=AsyncMock()) as revoke,
    ):
        await token.revoke_related_tokens()
    get.assert_awaited_once_with({
        "uid": "access-id",
        "tenant_id": "tenant",
        "is_deleted": False,
    })
    related.revoke.assert_awaited_once()
    revoke.assert_awaited_once()

    related.revoke.reset_mock()
    token = models.OAuthToken.model_construct(
        access_token_id=None, refresh_token="refresh", tenant_id="tenant"
    )
    with (
        patch.object(
            models.OAuthToken,
            "find_one",
            new=AsyncMock(return_value=related),
        ) as get,
        patch.object(models.OAuthToken, "revoke", new=AsyncMock()) as revoke,
    ):
        await token.revoke_related_tokens()
    assert get.await_count == 1
    related.revoke.assert_awaited_once()
    revoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_revoke_related_tokens_tolerates_missing_related_token() -> None:
    token = models.OAuthToken.model_construct(
        access_token_id="missing", refresh_token=None, tenant_id="tenant"
    )
    with (
        patch.object(models.OAuthToken, "find_one", new=AsyncMock(return_value=None)),
        patch.object(models.OAuthToken, "revoke", new=AsyncMock()) as revoke,
    ):
        await token.revoke_related_tokens()
    revoke.assert_awaited_once()


def test_oauth_session_factory_expiry_and_consent() -> None:
    def initialize(instance: object, **kwargs: object) -> None:
        instance.__dict__.update(kwargs)
        object.__setattr__(instance, "__pydantic_fields_set__", set(kwargs))
        object.__setattr__(instance, "__pydantic_extra__", None)
        object.__setattr__(instance, "__pydantic_private__", None)

    with patch.object(models.OAuthSession, "__init__", initialize):
        session = models.OAuthSession.create_session(
            client_id="client",
            user_id="user",
            tenant_id="tenant",
            scope=["openid", "profile"],
            redirect_uri="https://app.test/callback",
            state="state",
            nonce="nonce",
        )
    assert session.state == "state"
    session.grant_consent(["openid"])
    assert session.is_consented is True
    assert session.granted_scope == ["openid"]
    # is_expired() stamps naive values as timezone.tz (UTC).
    now_utc = datetime.now(timezone.tz).replace(tzinfo=None)
    session.expires_at = now_utc - timedelta(seconds=1)
    assert session.is_expired() is True
    session.expires_at = now_utc + timedelta(seconds=30)
    assert session.is_expired() is False


@pytest.mark.parametrize("aware", [False, True])
def test_device_authorization_expiry_handles_naive_and_aware_datetimes(
    aware: bool,
) -> None:
    expires_at = datetime.now(timezone.tz) - timedelta(seconds=1)
    if not aware:
        expires_at = expires_at.replace(tzinfo=None)
    authorization = models.OuathDeviceAuthorization.model_construct(
        expires_at=expires_at
    )
    assert authorization.is_expired() is True


@pytest.mark.asyncio
async def test_user_consent_covers_requires_all_scopes() -> None:
    stored = SimpleNamespace(scopes=["openid", "profile"])
    with patch.object(
        models.UserConsent, "find_one", new=AsyncMock(return_value=stored)
    ) as find:
        assert await models.UserConsent.covers("t", "u", "c", ["openid"])
        assert not await models.UserConsent.covers("t", "u", "c", ["openid", "write"])
    assert find.await_args.args[0] == {
        "tenant_id": "t",
        "user_id": "u",
        "client_id": "c",
    }
    with patch.object(models.UserConsent, "find_one", new=AsyncMock(return_value=None)):
        assert not await models.UserConsent.covers("t", "u", "c", ["openid"])


@pytest.mark.asyncio
async def test_user_consent_grant_creates_then_widens() -> None:
    # Document construction needs an initialised Beanie; stand in for the class.
    fake_cls = MagicMock()
    fake_cls.find_one = AsyncMock(return_value=None)
    fake_cls.return_value.save = AsyncMock()
    created = await models.UserConsent.grant.__func__(
        fake_cls, "t", "u", "c", ["profile", "openid"]
    )
    assert fake_cls.call_args.kwargs["scopes"] == ["openid", "profile"]
    created.save.assert_awaited_once()

    existing = SimpleNamespace(scopes=["openid"], save=AsyncMock())
    with patch.object(
        models.UserConsent, "find_one", new=AsyncMock(return_value=existing)
    ):
        await models.UserConsent.grant("t", "u", "c", ["write"])
    assert existing.scopes == ["openid", "write"]
    existing.save.assert_awaited_once()
