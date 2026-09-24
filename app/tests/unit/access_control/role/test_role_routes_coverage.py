"""Focused route coverage for role management."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.access_control.role import routes, schemas
from server.exceptions import ForbiddenError
from utils.usso_routes import AbstractTenantUSSORouter


@pytest.fixture(autouse=True)
def _mock_role_step_up() -> object:
    with (
        patch.object(
            routes.RoleRouter,
            "get_tenant",
            new=AsyncMock(return_value=SimpleNamespace(uid="t1")),
        ),
        patch.object(routes, "require_secure_token") as require,
    ):
        yield require


@pytest.mark.asyncio
async def test_list_items_delegates_filters() -> None:
    router = routes.RoleRouter()
    expected = object()
    list_items = AsyncMock(return_value=expected)
    request = MagicMock()

    with patch.object(router, "_list_items", new=list_items):
        result = await router.list_items(
            request, offset=4, limit=8, workspace_id="ws-1"
        )

    assert result is expected
    list_items.assert_awaited_once_with(
        request=request, offset=4, limit=8, workspace_id="ws-1"
    )


@pytest.mark.asyncio
async def test_create_item_delegates_when_scopes_are_subset() -> None:
    router = routes.RoleRouter()
    request = MagicMock()
    data = schemas.RoleCreateSchema(name="editor", scopes=["read:sso/usso/member"])
    user = SimpleNamespace(uid="u1", tenant_id="t1")
    user_model = SimpleNamespace(
        get_scopes=AsyncMock(return_value=["*:sso/usso/member"])
    )
    created = object()
    authorize = AsyncMock()

    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "authorize", new=authorize),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=user_model)),
        patch.object(routes.authorization, "has_subset_scope", return_value=True),
        patch.object(
            AbstractTenantUSSORouter,
            "create_item",
            new=AsyncMock(return_value=created),
        ) as base_create,
    ):
        result = await router.create_item(request, data)

    assert result is created
    authorize.assert_awaited_once()
    user_model.get_scopes.assert_awaited_once_with(None)
    base_create.assert_awaited_once_with(request, data)


@pytest.mark.asyncio
async def test_create_item_rejects_scope_caller_does_not_have() -> None:
    router = routes.RoleRouter()
    data = schemas.RoleCreateSchema(name="admin", scopes=["admin:sso/tenant"])
    user_model = SimpleNamespace(get_scopes=AsyncMock(return_value=["read:sso/tenant"]))

    with (
        patch.object(
            router,
            "get_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="u1", tenant_id="t1")),
        ),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=user_model)),
        patch.object(routes.authorization, "has_subset_scope", return_value=False),
        pytest.raises(ForbiddenError) as exc,
    ):
        await router.create_item(MagicMock(), data)
    assert exc.value.error_code == "scope_insufficient"


@pytest.mark.asyncio
async def test_update_item_rejects_scope_caller_does_not_have() -> None:
    router = routes.RoleRouter()
    item = SimpleNamespace(
        workspace_id="ws-1",
        model_dump=MagicMock(return_value={"name": "editor"}),
    )
    user_model = SimpleNamespace(get_scopes=AsyncMock(return_value=[]))

    with (
        patch.object(
            router,
            "get_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="u1", tenant_id="t1")),
        ),
        patch.object(router, "get_item", new=AsyncMock(return_value=item)),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=user_model)),
        patch.object(routes.authorization, "has_subset_scope", return_value=False),
        pytest.raises(ForbiddenError) as exc,
    ):
        await router.update_item(
            MagicMock(),
            "role-1",
            schemas.RoleUpdateSchema(scopes=["write:sso/usso/member"]),
        )
    assert exc.value.error_code == "scope_insufficient"


@pytest.mark.asyncio
async def test_update_item_propagates_successful_scope_change() -> None:
    router = routes.RoleRouter()
    request = MagicMock()
    current = SimpleNamespace(
        workspace_id="ws-1",
        model_dump=MagicMock(return_value={"name": "editor"}),
    )
    updated = SimpleNamespace(tenant_id="t1", name="editor", workspace_id="ws-1")
    user = SimpleNamespace(uid="u1", tenant_id="t1")
    user_model = SimpleNamespace(
        get_scopes=AsyncMock(return_value=["*:sso/usso/member"])
    )

    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_item", new=AsyncMock(return_value=current)),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=user_model)),
        patch.object(routes.authorization, "has_subset_scope", return_value=True),
        patch.object(
            AbstractTenantUSSORouter,
            "update_item",
            new=AsyncMock(return_value=updated),
        ) as base_update,
        patch.object(
            routes.User, "propagate_role_scope_change", new=AsyncMock()
        ) as propagate,
    ):
        result = await router.update_item(
            request, "role-1", schemas.RoleUpdateSchema(scopes=["read:sso/usso/member"])
        )

    assert result is updated
    base_update.assert_awaited_once_with(
        request, "role-1", {"scopes": ["read:sso/usso/member"]}
    )
    propagate.assert_awaited_once_with(
        tenant_id="t1", role_name="editor", role_workspace_id="ws-1"
    )


@pytest.mark.asyncio
async def test_delete_role_requires_step_up_and_propagates() -> None:
    router = routes.RoleRouter()
    request = MagicMock()
    user = SimpleNamespace(uid="u1", tenant_id="t1")
    deleted = SimpleNamespace(tenant_id="t1", name="editor", workspace_id="ws-1")
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(
            AbstractTenantUSSORouter,
            "delete_item",
            new=AsyncMock(return_value=deleted),
        ) as base_delete,
        patch.object(
            routes.User, "propagate_role_scope_change", new=AsyncMock()
        ) as propagate,
    ):
        assert await router.delete_item(request, "role-1") is deleted
    base_delete.assert_awaited_once_with(request, "role-1")
    propagate.assert_awaited_once_with(
        tenant_id="t1", role_name="editor", role_workspace_id="ws-1"
    )
