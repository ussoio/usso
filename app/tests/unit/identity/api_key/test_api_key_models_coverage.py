"""Coverage for API-key scope-capping and cache invalidation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.api_key.models import APIKey


@pytest.mark.asyncio
async def test_cap_user_api_key_scopes_saves_and_invalidates_changed_keys() -> None:
    changed = SimpleNamespace(uid="key-1", scopes=["read", "admin"], save=AsyncMock())
    unchanged = SimpleNamespace(uid="key-2", scopes=["read"], save=AsyncMock())
    empty = SimpleNamespace(uid="key-3", scopes=None, save=AsyncMock())
    query_result = SimpleNamespace(
        to_list=AsyncMock(return_value=[changed, unchanged, empty])
    )
    find = MagicMock(return_value=query_result)
    invalidate = AsyncMock()

    with (
        patch.object(APIKey, "find", new=find),
        patch(
            "apps.identity.api_key.models.authorization.has_subset_scope",
            side_effect=lambda *, subset_scope, user_scopes: (
                subset_scope in user_scopes
            ),
        ),
        patch(
            "apps.identity.api_key.services.invalidate_api_key_cache",
            new=invalidate,
        ),
    ):
        count = await APIKey.cap_user_api_keys_scopes(
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
    invalidate.assert_awaited_once_with(uid="key-1")
    find.assert_called_once_with({
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "is_deleted": False,
        "workspace_id": "workspace-1",
    })


@pytest.mark.asyncio
async def test_cap_user_api_key_scopes_empty_query() -> None:
    query_result = SimpleNamespace(to_list=AsyncMock(return_value=[]))
    with patch.object(APIKey, "find", return_value=query_result):
        assert (
            await APIKey.cap_user_api_keys_scopes(
                user_id="user-1", tenant_id="tenant-1", user_scopes=[]
            )
            == 0
        )
