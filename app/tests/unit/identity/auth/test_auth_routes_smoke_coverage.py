"""Fast smoke coverage for small authentication route handlers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Response

from apps.identity.auth import routes
from apps.identity.auth.enums import (
    AuthIdentifier,
    AuthSecret,
    OTPDeliveryStatus,
)
from apps.identity.auth.schemas import MagicLinkRequest, VerifyTokenRequest


@pytest.mark.asyncio
async def test_get_all_route_returns_registered_route_strings() -> None:
    result = await routes.get_all_route()
    assert result
    assert all(isinstance(route, str) for route in result)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result",
    [
        SimpleNamespace(
            user=None, otp_delivery={AuthSecret.PHONE_OTP: OTPDeliveryStatus.SENT}
        ),
        SimpleNamespace(user=object(), otp_delivery={}),
    ],
)
async def test_auto_send_otp_returns_early_without_user_or_delivery(
    result: object,
) -> None:
    with patch.object(routes, "create_otp", new=AsyncMock()) as create_otp:
        await routes._auto_send_otp(result, object(), None)
    create_otp.assert_not_awaited()


@pytest.mark.asyncio
async def test_auto_send_otp_sends_phone_and_email_identifiers() -> None:
    identifiers = [
        SimpleNamespace(type=AuthIdentifier.PHONE, identifier="09120000000"),
        SimpleNamespace(type=AuthIdentifier.EMAIL, identifier="user@example.com"),
        SimpleNamespace(type=AuthIdentifier.USERNAME, identifier="ignored"),
    ]
    user = SimpleNamespace(get_identifiers=AsyncMock(return_value=identifiers))
    result = SimpleNamespace(
        user=user,
        otp_delivery={
            AuthSecret.PHONE_OTP: OTPDeliveryStatus.SENT,
            AuthSecret.EMAIL_OTP: OTPDeliveryStatus.SENT,
            AuthSecret.TOTP: OTPDeliveryStatus.REQUESTABLE,
        },
    )
    tenant = object()
    with patch.object(routes, "create_otp", new=AsyncMock()) as create_otp:
        await routes._auto_send_otp(result, tenant, "https://app.test")

    assert create_otp.await_count == 2
    phone_request = create_otp.await_args_list[0].kwargs["otp_request"]
    email_request = create_otp.await_args_list[1].kwargs["otp_request"]
    assert (phone_request.type, phone_request.identifier) == (
        AuthIdentifier.PHONE,
        "989120000000",
    )
    assert (email_request.type, email_request.identifier) == (
        AuthIdentifier.EMAIL,
        "user@example.com",
    )


def _logout_tenant(payload: object = None) -> tuple[SimpleNamespace, MagicMock]:
    refresh_auth = MagicMock(return_value=payload)
    tenant = SimpleNamespace(
        refresh_auth=refresh_auth,
        domains=["sso.test"],
        primary_domain="primary.test",
    )
    return tenant, refresh_auth


@pytest.mark.asyncio
async def test_logout_without_refresh_payload_only_removes_cookies() -> None:
    request = MagicMock()
    request.url.hostname = "outside.test"
    tenant, refresh_auth = _logout_tenant()
    removed = Response(status_code=204)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "check_session_validity", new=AsyncMock()
        ) as check_session,
        patch.object(routes, "remove_auth_cookies", return_value=removed) as remove,
    ):
        result = await routes.logout(request)
    assert result is removed
    assert refresh_auth.raise_exception is False
    check_session.assert_not_awaited()
    assert remove.call_args.kwargs["domain"] == "primary.test"


@pytest.mark.asyncio
async def test_logout_soft_deletes_existing_session() -> None:
    request = MagicMock()
    request.url.hostname = "sso.test"
    payload = object()
    tenant, _ = _logout_tenant(payload)
    session = SimpleNamespace(is_deleted=False, save=AsyncMock())
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "check_session_validity",
            new=AsyncMock(return_value=session),
        ) as check_session,
        patch.object(
            routes, "remove_auth_cookies", side_effect=lambda **kw: kw["response"]
        ) as remove,
    ):
        response = await routes.logout(request)
    assert response.status_code == 204
    assert session.is_deleted is True
    session.save.assert_awaited_once()
    check_session.assert_awaited_once_with(
        refresh_payload=payload, raise_exception=False
    )
    assert remove.call_args.kwargs["domain"] == "sso.test"


@pytest.mark.asyncio
async def test_logout_post_delegates_to_logout() -> None:
    request = MagicMock()
    response = Response(status_code=204)
    with patch.object(routes, "logout", new=AsyncMock(return_value=response)) as logout:
        assert await routes.logout_post(request) is response
    logout.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_verify_token_uses_requested_tenant_authenticator() -> None:
    request = MagicMock()
    data = VerifyTokenRequest(token="encoded-token", token_type="access")
    payload = object()
    auth = SimpleNamespace(user_data_from_token=MagicMock(return_value=payload))
    tenant = SimpleNamespace(get_auth=MagicMock(return_value=auth))
    with patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)):
        result = await routes.verify_token(request, data)
    assert result is payload
    tenant.get_auth.assert_called_once_with(data.token_type)
    auth.user_data_from_token.assert_called_once_with(
        "encoded-token", expected_token_type=data.token_type
    )


@pytest.mark.asyncio
async def test_me_authenticates_with_access_token() -> None:
    request = MagicMock()
    payload = object()
    auth = MagicMock(return_value=payload)
    tenant = SimpleNamespace(get_auth=MagicMock(return_value=auth))
    with patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)):
        result = await routes.me(request)
    assert result is payload
    tenant.get_auth.assert_called_once_with("access")
    auth.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_magic_link_request_delegates_sender() -> None:
    request = MagicMock()
    request.headers.get.return_value = "https://app.test"
    tenant = object()
    data = MagicLinkRequest(type=AuthIdentifier.EMAIL, identifier="user@example.com")
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "send_magic_link", new=AsyncMock()) as send,
    ):
        result = await routes.magic_link_request(request, Response(), data)
    assert result == {"status": "success"}
    send.assert_awaited_once_with(tenant=tenant, origin="https://app.test", data=data)
