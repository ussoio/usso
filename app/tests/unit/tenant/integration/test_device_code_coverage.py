"""Focused service coverage for OAuth device authorization."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.tenant.integration import device_code as dc
from apps.tenant.integration.schemas import (
    GrantType,
    OuathDeviceAuthorizationStatus,
    Scope,
)
from server.exceptions import BadRequestError, NotFoundError


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        get_frontend_url=MagicMock(return_value="https://sso.test/device?lang=en"),
    )


def _client(**overrides: object) -> SimpleNamespace:
    values = {
        "uid": "device-auth-1",
        "client_id": "client-1",
        "user_id": "owner-1",
        "grant_types": [GrantType.DEVICE_CODE],
        "allowed_scopes": [Scope.OPENID, Scope.PROFILE],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _auth(**overrides: object) -> SimpleNamespace:
    values = {
        "uid": "device-auth-1",
        "client_id": "client-1",
        "scope": ["openid", "profile"],
        "granted_scope": None,
        "status": OuathDeviceAuthorizationStatus.AUTHORIZED,
        "authorized_user_id": "user-1",
        "is_consumed": False,
        "expires_at": datetime.now(timezone.tz) + timedelta(minutes=5),
        "last_polled_at": None,
        "interval": 5,
        "save": AsyncMock(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _error_code(exc: pytest.ExceptionInfo[BadRequestError], expected: str) -> None:
    assert exc.value.error_code == expected


def test_build_verification_uri_complete_uses_existing_query() -> None:
    assert (
        dc.build_verification_uri_complete(
            "https://sso.test/device?lang=en", "ABCD-EFGH"
        )
        == "https://sso.test/device?lang=en&user_code=ABCD-EFGH"
    )


@pytest.mark.parametrize(
    ("allowed", "scope", "expected"),
    [
        ([Scope.OPENID, Scope.PROFILE], None, ["openid"]),
        ([Scope.PROFILE, Scope.EMAIL], "", ["profile"]),
        (
            [SimpleNamespace(value="email"), Scope.PROFILE],
            "email profile",
            ["email", "profile"],
        ),
    ],
)
def test_resolve_device_scopes_defaults_and_enum_items(
    allowed: list[object], scope: str | None, expected: list[str]
) -> None:
    assert dc.resolve_device_scopes(_client(allowed_scopes=allowed), scope) == expected


def test_assert_poll_interval_accepts_first_poll_and_handles_naive_time() -> None:
    now = datetime.now(timezone.tz)
    dc.assert_poll_interval(_auth(last_polled_at=None), now=now)
    recent_naive = now.replace(tzinfo=None) - timedelta(seconds=1)
    auth = _auth(last_polled_at=recent_naive, interval=5)
    with pytest.raises(BadRequestError) as exc:
        dc.assert_poll_interval(auth, now=now)
    _error_code(exc, "slow_down")
    assert auth.interval == 10


@pytest.mark.parametrize("consumed", [True, False])
def test_raise_if_not_ready_consumed_or_naively_expired(consumed: bool) -> None:
    # Naive expires_at is treated as timezone.tz (UTC); keep wall clock in UTC.
    now_utc = datetime.now(timezone.tz).replace(tzinfo=None)
    expires = (
        now_utc + timedelta(minutes=5)
        if consumed
        else now_utc - timedelta(seconds=1)
    )
    with pytest.raises(BadRequestError) as exc:
        dc.raise_if_not_ready(_auth(is_consumed=consumed, expires_at=expires))
    _error_code(exc, "expired_token")


@pytest.mark.asyncio
async def test_create_device_authorization_rejects_unauthorized_client() -> None:
    with pytest.raises(BadRequestError) as exc:
        await dc.create_device_authorization(
            tenant=_tenant(), client=_client(grant_types=[]), scope="openid"
        )
    _error_code(exc, "unauthorized_client")


@pytest.mark.asyncio
async def test_create_device_authorization_rejects_invalid_scope() -> None:
    with pytest.raises(BadRequestError) as exc:
        await dc.create_device_authorization(
            tenant=_tenant(), client=_client(), scope="admin"
        )
    _error_code(exc, "invalid_scope")


@pytest.mark.asyncio
async def test_create_device_authorization_success_with_existing_query_uri() -> None:
    saved: list[object] = []

    class FakeAuthorization:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

        async def save(self) -> None:
            saved.append(self)

    with (
        patch.object(dc.models, "OuathDeviceAuthorization", FakeAuthorization),
        patch.object(dc, "generate_user_code", return_value="ABCD-EFGH"),
        patch.object(dc, "generate_device_code", return_value="device-code"),
    ):
        result = await dc.create_device_authorization(
            tenant=_tenant(), client=_client(), scope=None
        )
    assert result.device_code == "device-code"
    assert "?lang=en&user_code=ABCD-EFGH" in result.verification_uri_complete
    assert saved[0].scope == ["openid"]


@pytest.mark.asyncio
async def test_get_pending_by_user_code_found_and_not_found() -> None:
    auth = _auth()
    with patch.object(
        dc.models.OuathDeviceAuthorization,
        "find_one",
        new_callable=AsyncMock,
        return_value=auth,
    ) as find:
        assert (
            await dc.get_pending_by_user_code(
                tenant_id="tenant-1", user_code="abcd efgh"
            )
            is auth
        )
    assert find.await_args.args[0]["user_code_normalized"] == "ABCDEFGH"

    with (
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "find_one",
            new_callable=AsyncMock,
            return_value=None,
        ),
        pytest.raises(NotFoundError) as exc,
    ):
        await dc.get_pending_by_user_code(tenant_id="tenant-1", user_code="bad")
    assert exc.value.error_code == "invalid_user_code"


@pytest.mark.asyncio
async def test_approve_device_authorization_deny() -> None:
    auth = _auth(status=OuathDeviceAuthorizationStatus.PENDING)
    user = SimpleNamespace(uid="user-1")
    with patch.object(
        dc, "get_pending_by_user_code", new_callable=AsyncMock, return_value=auth
    ):
        result = await dc.approve_device_authorization(
            tenant=_tenant(), user=user, user_code="ABCD-EFGH", approve=False
        )
    assert result.status == OuathDeviceAuthorizationStatus.DENIED
    assert result.authorized_user_id == "user-1"
    auth.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_approve_device_authorization_filters_granted_scope() -> None:
    auth = _auth(status=OuathDeviceAuthorizationStatus.PENDING)
    with (
        patch.object(
            dc, "get_pending_by_user_code", new_callable=AsyncMock, return_value=auth
        ),
        patch.object(
            dc, "validate_client", new_callable=AsyncMock, return_value=_client()
        ),
    ):
        result = await dc.approve_device_authorization(
            tenant=_tenant(),
            user=SimpleNamespace(uid="user-1"),
            user_code="ABCD-EFGH",
            approve=True,
            granted_scope=["profile", "admin"],
        )
    assert result.status == OuathDeviceAuthorizationStatus.AUTHORIZED
    assert result.granted_scope == ["profile"]
    auth.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_exchange_device_code_rejects_unauthorized_client() -> None:
    with (
        patch.object(
            dc,
            "validate_client",
            new_callable=AsyncMock,
            return_value=_client(grant_types=[]),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await dc.exchange_device_code(
            tenant=_tenant(), client_id="client-1", device_code="device"
        )
    _error_code(exc, "unauthorized_client")


@pytest.mark.asyncio
async def test_exchange_device_code_rejects_invalid_code() -> None:
    with (
        patch.object(
            dc, "validate_client", new_callable=AsyncMock, return_value=_client()
        ),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "find_one",
            new_callable=AsyncMock,
            return_value=None,
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await dc.exchange_device_code(
            tenant=_tenant(), client_id="client-1", device_code="bad"
        )
    _error_code(exc, "invalid_grant")


@pytest.mark.asyncio
async def test_exchange_device_code_slow_down_saves_interval() -> None:
    auth = _auth(last_polled_at=datetime.now(timezone.tz))
    with (
        patch.object(
            dc, "validate_client", new_callable=AsyncMock, return_value=_client()
        ),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "find_one",
            new_callable=AsyncMock,
            return_value=auth,
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await dc.exchange_device_code(
            tenant=_tenant(), client_id="client-1", device_code="device"
        )
    _error_code(exc, "slow_down")
    assert auth.interval == 10
    auth.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_exchange_device_code_authorization_pending() -> None:
    auth = _auth(status=OuathDeviceAuthorizationStatus.PENDING)
    with (
        patch.object(
            dc, "validate_client", new_callable=AsyncMock, return_value=_client()
        ),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "find_one",
            new_callable=AsyncMock,
            return_value=auth,
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await dc.exchange_device_code(
            tenant=_tenant(), client_id="client-1", device_code="device"
        )
    _error_code(exc, "authorization_pending")
    auth.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_exchange_device_code_rejects_missing_authorized_user() -> None:
    auth = _auth()
    collection = MagicMock(
        update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1))
    )
    with (
        patch.object(
            dc, "validate_client", new_callable=AsyncMock, return_value=_client()
        ),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "find_one",
            new_callable=AsyncMock,
            return_value=auth,
        ),
        patch.object(dc.User, "get_item", new_callable=AsyncMock, return_value=None),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "get_pymongo_collection",
            return_value=collection,
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await dc.exchange_device_code(
            tenant=_tenant(), client_id="client-1", device_code="device"
        )
    _error_code(exc, "invalid_grant")


@pytest.mark.asyncio
async def test_exchange_device_code_success_consumes_authorization() -> None:
    auth = _auth(granted_scope=["profile"])
    tokens = SimpleNamespace(access_token="token")
    user = SimpleNamespace(uid="user-1")
    client = _client()
    collection = MagicMock(
        update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1))
    )
    with (
        patch.object(
            dc, "validate_client", new_callable=AsyncMock, return_value=client
        ),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "find_one",
            new_callable=AsyncMock,
            return_value=auth,
        ),
        patch.object(dc.User, "get_item", new_callable=AsyncMock, return_value=user),
        patch.object(
            dc.models.OuathDeviceAuthorization,
            "get_pymongo_collection",
            return_value=collection,
        ),
        patch.object(
            dc, "create_tokens", new_callable=AsyncMock, return_value=tokens
        ) as create,
    ):
        result = await dc.exchange_device_code(
            tenant=_tenant(), client_id="client-1", device_code="device"
        )
    assert result is tokens
    assert auth.is_consumed is True
    assert auth.save.await_count == 1
    assert create.await_args.kwargs["scope"] == ["profile"]
