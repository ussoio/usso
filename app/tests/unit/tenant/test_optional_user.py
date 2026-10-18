"""Tests for Tenant.optional_user / optional_user_async credential gating."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from apps.tenant.models import Tenant


def _tenant(auth: object) -> Tenant:
    tenant = Tenant.model_construct()
    object.__setattr__(tenant, "get_auth", MagicMock(return_value=auth))
    return tenant


def test_optional_user_returns_none_without_credentials() -> None:
    auth = MagicMock()
    auth.get_request_jwt.return_value = None
    auth.get_request_api_key.return_value = None
    request = object()

    tenant = _tenant(auth)
    assert tenant.optional_user(request) is None

    tenant.get_auth.assert_called_once_with("temporary", raise_exception=False)
    auth.assert_not_called()


def test_optional_user_returns_auth_result_when_jwt_present() -> None:
    auth = MagicMock()
    auth.get_request_jwt.return_value = "jwt-token"
    auth.get_request_api_key.return_value = None
    result = object()
    auth.return_value = result
    request = object()

    tenant = _tenant(auth)
    assert tenant.optional_user(request) is result

    auth.assert_called_once_with(request)


def test_optional_user_returns_auth_result_when_api_key_present() -> None:
    auth = MagicMock()
    auth.get_request_jwt.return_value = None
    auth.get_request_api_key.return_value = "api-key"
    result = object()
    auth.return_value = result
    request = object()

    tenant = _tenant(auth)
    assert tenant.optional_user(request, "access") is result

    tenant.get_auth.assert_called_once_with("access", raise_exception=False)
    auth.assert_called_once_with(request)


async def test_optional_user_async_returns_none_without_credentials() -> None:
    auth = MagicMock()
    auth.get_request_jwt.return_value = None
    auth.get_request_api_key.return_value = None
    request = object()

    tenant = _tenant(auth)
    assert await tenant.optional_user_async(request) is None

    auth.usso_access_security_async.assert_not_called()


async def test_optional_user_async_awaits_security_when_credentials_exist() -> None:
    auth = MagicMock()
    auth.get_request_jwt.return_value = "jwt-token"
    auth.get_request_api_key.return_value = None
    result = object()
    auth.usso_access_security_async = AsyncMock(return_value=result)
    request = object()

    tenant = _tenant(auth)
    assert await tenant.optional_user_async(request, "temporary") is result

    auth.usso_access_security_async.assert_awaited_once_with(request)
