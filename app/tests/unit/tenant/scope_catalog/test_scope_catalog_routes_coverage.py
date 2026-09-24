"""Focused route coverage for the tenant scope catalog."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.tenant.scope_catalog import routes, schemas


@pytest.mark.asyncio
async def test_list_items_normalizes_optional_filters() -> None:
    router = routes.ScopeCatalogRouter()
    list_items = AsyncMock(return_value="page")
    request = MagicMock()

    with patch.object(router, "_list_items", new=list_items):
        result = await router.list_items(
            request,
            offset=2,
            limit=25,
            service=" Media ",
            source=schemas.ScopeCatalogSource.MANUAL,
            scope=" read:file/items ",
        )

    assert result == "page"
    list_items.assert_awaited_once_with(
        request=request,
        offset=2,
        limit=25,
        service="media",
        source=schemas.ScopeCatalogSource.MANUAL,
        scope="read:file/items",
    )


@pytest.mark.asyncio
async def test_sync_service_scopes_authorizes_and_delegates() -> None:
    router = routes.ScopeCatalogRouter()
    request = MagicMock()
    user = SimpleNamespace(uid="u1")
    tenant = SimpleNamespace(uid="t1")
    data = schemas.ScopeCatalogSyncSchema(
        scopes=[schemas.ScopeCatalogItemIn(scope="read:file/items")]
    )
    expected = [object()]
    authorize = AsyncMock()

    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "authorize", new=authorize),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.services,
            "sync_service_scopes",
            new=AsyncMock(return_value=expected),
        ) as sync,
    ):
        result = await router.sync_service_scopes(request, " Media ", data)

    assert result is expected
    authorize.assert_awaited_once_with(
        action="manage", user=user, filter_data={"service": "media"}
    )
    sync.assert_awaited_once_with(tenant_id="t1", service=" Media ", items=data.scopes)


@pytest.mark.asyncio
async def test_create_item_authorizes_and_uses_manual_service() -> None:
    router = routes.ScopeCatalogRouter()
    request = MagicMock()
    user = SimpleNamespace(uid="u1")
    tenant = SimpleNamespace(uid="t1")
    data = schemas.ScopeCatalogCreateSchema(service="media", scope="manage:file/items")
    created = object()
    authorize = AsyncMock()

    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "authorize", new=authorize),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.services,
            "create_manual_entry",
            new=AsyncMock(return_value=created),
        ) as create,
    ):
        result = await router.create_item(request, data)

    assert result is created
    authorize.assert_awaited_once_with(
        action="create", user=user, filter_data=data.model_dump()
    )
    create.assert_awaited_once_with(tenant_id="t1", data=data)


@pytest.mark.asyncio
async def test_update_item_only_forwards_display_metadata() -> None:
    router = routes.ScopeCatalogRouter()
    request = MagicMock()
    data = schemas.ScopeCatalogUpdateSchema(label="Media scopes")

    with patch(
        "utils.usso_routes.usso_routes.AbstractTenantUSSORouter.update_item",
        new=AsyncMock(return_value="updated"),
    ) as update:
        result = await router.update_item(request, "scope-1", data)

    assert result == "updated"
    update.assert_awaited_once_with(
        request,
        "scope-1",
        {"label": "Media scopes"},
    )


def test_get_list_filter_queries_denies_without_matching_scope() -> None:
    router = routes.ScopeCatalogRouter()
    user = SimpleNamespace(scopes=[])
    with patch("usso.authorization.get_scope_filters", return_value=[]):
        assert router.get_list_filter_queries(user=user) == {"__deny__": True}


def test_get_list_filter_queries_returns_broadest_filter() -> None:
    router = routes.ScopeCatalogRouter()
    user = SimpleNamespace(scopes=["read:sso/scope-catalog"])
    matches = [{"service": "media"}, {"service": "files"}]
    with (
        patch("usso.authorization.get_scope_filters", return_value=matches),
        patch(
            "usso.authorization.broadest_scope_filter",
            return_value={"service": {"$in": ["media", "files"]}},
        ) as broadest,
    ):
        result = router.get_list_filter_queries(user=user)
    assert result == {"service": {"$in": ["media", "files"]}}
    broadest.assert_called_once_with(matches)
