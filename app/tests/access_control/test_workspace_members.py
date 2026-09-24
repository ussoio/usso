"""Tests for workspace member listing."""

from unittest.mock import AsyncMock, patch

import pytest

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import WorkspaceMemberSchema
from apps.identity.user.models import User


@pytest.mark.asyncio
async def test_list_workspace_members_returns_roles_for_workspace() -> None:
    """Members include only roles assigned in the requested workspace."""
    member = User(
        uid="user_1",
        name="Member One",
        tenant_id="tenant_1",
        is_active=True,
        workspace_ids=["ws_1"],
        workspace_roles={"ws_1": ["CEO"], "ws_2": ["editor"]},
    )
    with patch.object(
        User,
        "list_total_combined",
        new=AsyncMock(return_value=([member], 1)),
    ):
        items, total = await services.list_workspace_members(
            workspace_id="ws_1",
            tenant_id="tenant_1",
            offset=0,
            limit=10,
        )

    assert total == 1
    assert items == [
        WorkspaceMemberSchema(
            uid="user_1",
            name="Member One",
            roles=["CEO"],
            is_active=True,
            avatar_url=None,
        )
    ]


@pytest.mark.asyncio
async def test_list_workspace_members_passes_workspace_filter() -> None:
    """Service queries users by workspace membership."""
    with patch.object(
        User,
        "list_total_combined",
        new=AsyncMock(return_value=([], 0)),
    ) as list_mock:
        await services.list_workspace_members(
            workspace_id="ws_9",
            tenant_id="tenant_1",
            offset=5,
            limit=20,
        )

    list_mock.assert_awaited_once_with(
        tenant_id="tenant_1",
        offset=5,
        limit=20,
        workspace_ids="ws_9",
    )
