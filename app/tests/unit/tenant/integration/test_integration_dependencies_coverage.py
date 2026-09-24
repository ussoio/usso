"""Focused unit coverage for OAuth integration authentication dependencies."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from apps.tenant.integration import dependencies
from server.exceptions import UnauthorizedError


@pytest.mark.asyncio
async def test_get_current_user_resolves_payload_and_database_user() -> None:
    request = MagicMock()
    auth = MagicMock(return_value=SimpleNamespace(sub="user-1"))
    tenant = SimpleNamespace(uid="tenant-1", get_auth=MagicMock(return_value=auth))
    user = SimpleNamespace(uid="user-1")
    with (
        patch.object(dependencies, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            dependencies.User, "get_item", new=AsyncMock(return_value=user)
        ) as get,
    ):
        assert await dependencies.get_current_user(request) is user
    tenant.get_auth.assert_called_once_with("access")
    auth.assert_called_once_with(request)
    get.assert_awaited_once_with(uid="user-1", tenant_id="tenant-1")


@pytest.mark.asyncio
async def test_get_current_user_raises_when_database_user_is_missing() -> None:
    tenant = SimpleNamespace(
        uid="tenant-1",
        get_auth=MagicMock(
            return_value=MagicMock(return_value=SimpleNamespace(sub="missing"))
        ),
    )
    with (
        patch.object(dependencies, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(dependencies.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await dependencies.get_current_user(MagicMock())
    assert exc.value.error_code == "user_not_found"


@pytest.mark.asyncio
async def test_optional_current_user_returns_user_or_none_for_auth_errors() -> None:
    user = SimpleNamespace(uid="user-1")
    with patch.object(
        dependencies, "get_current_user", new=AsyncMock(return_value=user)
    ):
        assert await dependencies.get_current_user_optional(MagicMock()) is user

    with patch.object(
        dependencies,
        "get_current_user",
        new=AsyncMock(side_effect=HTTPException(status_code=401)),
    ):
        assert await dependencies.get_current_user_optional(MagicMock()) is None
