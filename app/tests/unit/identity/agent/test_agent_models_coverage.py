"""Coverage for Agent scope-capping persistence helper."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.agent.models import Agent


@pytest.mark.asyncio
async def test_cap_user_agents_scopes_updates_only_changed_agents() -> None:
    changed = SimpleNamespace(scopes=["read", "admin"], save=AsyncMock())
    unchanged = SimpleNamespace(scopes=["read"], save=AsyncMock())
    empty = SimpleNamespace(scopes=None, save=AsyncMock())
    query_result = SimpleNamespace(
        to_list=AsyncMock(return_value=[changed, unchanged, empty])
    )
    find = MagicMock(return_value=query_result)

    with (
        patch.object(Agent, "find", new=find),
        patch(
            "apps.identity.agent.models.authorization.has_subset_scope",
            side_effect=lambda *, subset_scope, user_scopes: (
                subset_scope in user_scopes
            ),
        ),
    ):
        count = await Agent.cap_user_agents_scopes(
            user_id="user-1",
            tenant_id="tenant-1",
            user_scopes=["read"],
            workspace_id="workspace-1",
        )

    assert count == 1
    assert changed.scopes == ["read"]
    changed.save.assert_awaited_once()
    unchanged.save.assert_not_awaited()
    empty.save.assert_not_awaited()
    find.assert_called_once_with({
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "is_deleted": False,
        "workspace_id": "workspace-1",
    })


@pytest.mark.asyncio
async def test_cap_user_agents_scopes_empty_query() -> None:
    query_result = SimpleNamespace(to_list=AsyncMock(return_value=[]))
    with patch.object(Agent, "find", return_value=query_result):
        assert (
            await Agent.cap_user_agents_scopes(
                user_id="user-1", tenant_id="tenant-1", user_scopes=[]
            )
            == 0
        )
