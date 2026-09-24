"""Unit tests for scope catalog sync helpers."""

from types import SimpleNamespace
from unittest import mock

import pytest

from apps.tenant.scope_catalog import schemas, services


def test_parse_scope_fields_splits_action_and_path() -> None:
    """Scope strings yield action + resource_path for indexing."""
    action, resource_path = services.parse_scope_fields("manage:file/media/files")
    assert action == "manage"
    assert resource_path == "file/media/files"


def test_normalize_service_name() -> None:
    """Service names are lowercased and trimmed."""
    assert services.normalize_service_name(" Media ") == "media"


@pytest.mark.asyncio
async def test_sync_replaces_service_entries_preserves_manual() -> None:
    """Service sync upserts/deletes service rows and leaves manual rows."""
    manual = SimpleNamespace(
        scope="manage:file/media/legacy",
        source=schemas.ScopeCatalogSource.MANUAL,
        service="media",
    )
    stale = SimpleNamespace(
        scope="manage:file/media/old",
        source=schemas.ScopeCatalogSource.SERVICE,
        service="media",
    )
    current = SimpleNamespace(
        scope="manage:file/media/files",
        source=schemas.ScopeCatalogSource.SERVICE,
        service="media",
    )
    created = SimpleNamespace(
        scope="read:file/media/files",
        source=schemas.ScopeCatalogSource.SERVICE,
        service="media",
    )
    updated = SimpleNamespace(
        scope="manage:file/media/files",
        source=schemas.ScopeCatalogSource.SERVICE,
        service="media",
    )

    find_chain = mock.MagicMock()
    find_chain.to_list = mock.AsyncMock(return_value=[manual, stale, current])

    with (
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.find",
            return_value=find_chain,
        ) as find_mock,
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.find_one",
            new_callable=mock.AsyncMock,
            return_value=None,
        ),
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.delete_item",
            new_callable=mock.AsyncMock,
        ) as delete_mock,
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.update_item",
            new_callable=mock.AsyncMock,
            return_value=updated,
        ) as update_mock,
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.create_item",
            new_callable=mock.AsyncMock,
            return_value=created,
        ) as create_mock,
    ):
        result = await services.sync_service_scopes(
            tenant_id="t1",
            service="Media",
            items=[
                schemas.ScopeCatalogItemIn(
                    scope="manage:file/media/files",
                    label_fa="مدیریت فایلها",
                ),
                schemas.ScopeCatalogItemIn(scope="read:file/media/files"),
            ],
        )

    find_mock.assert_called_once()
    assert find_mock.call_args.args[0]["service"] == "media"
    delete_mock.assert_awaited_once_with(stale)
    update_mock.assert_awaited()
    create_mock.assert_awaited()
    scopes = {row.scope for row in result}
    assert scopes == {
        "manage:file/media/legacy",
        "manage:file/media/files",
        "read:file/media/files",
    }


@pytest.mark.asyncio
async def test_sync_revives_soft_deleted_service_entry() -> None:
    """Re-pushing a previously deleted scope reuses the soft-deleted row."""
    deleted = SimpleNamespace(
        scope="manage:file/media/files",
        source=schemas.ScopeCatalogSource.SERVICE,
        service="media",
        is_deleted=True,
    )
    revived = SimpleNamespace(
        scope="manage:file/media/files",
        source=schemas.ScopeCatalogSource.SERVICE,
        service="media",
        is_deleted=False,
    )
    find_chain = mock.MagicMock()
    find_chain.to_list = mock.AsyncMock(return_value=[])

    with (
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.find",
            return_value=find_chain,
        ),
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.find_one",
            new_callable=mock.AsyncMock,
            return_value=deleted,
        ),
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.update_item",
            new_callable=mock.AsyncMock,
            return_value=revived,
        ) as update_mock,
        mock.patch(
            "apps.tenant.scope_catalog.services.models.ScopeCatalog.create_item",
            new_callable=mock.AsyncMock,
        ) as create_mock,
    ):
        result = await services.sync_service_scopes(
            tenant_id="t1",
            service="media",
            items=[schemas.ScopeCatalogItemIn(scope="manage:file/media/files")],
        )

    update_mock.assert_awaited_once()
    create_mock.assert_not_awaited()
    assert result == [revived]


@pytest.mark.asyncio
async def test_create_manual_entry_sets_source() -> None:
    """Manual create stores source=manual and parsed path fields."""
    created = SimpleNamespace(scope="manage:file/media/files")
    with mock.patch(
        "apps.tenant.scope_catalog.services.models.ScopeCatalog.create_item",
        new_callable=mock.AsyncMock,
        return_value=created,
    ) as create_mock:
        result = await services.create_manual_entry(
            tenant_id="t1",
            data=schemas.ScopeCatalogCreateSchema(
                service="media",
                scope="manage:file/media/files",
                label_fa="مدیریت فایلها",
            ),
        )

    assert result is created
    payload = create_mock.await_args.args[0]
    assert payload["source"] == schemas.ScopeCatalogSource.MANUAL
    assert payload["action"] == "manage"
    assert payload["resource_path"] == "file/media/files"


def test_resource_paths_core_only_when_features_disabled() -> None:
    """Disabled workspace/agents omit optional resource paths."""
    from apps.tenant.config import TenantConfig
    from apps.tenant.scope_catalog import bootstrap

    paths = bootstrap.resource_paths_for_tenant(
        TenantConfig(
            workspace={"enabled": False},
            agents={"enabled": False},
            integration={"api_key": {"enabled": False}},
        )
    )
    assert "sso/usso/user" in paths
    assert "sso/usso/workspace" not in paths
    assert "sso/usso/member" not in paths
    assert "sso/usso/workspace_invitation" not in paths
    assert "sso/usso/agent" not in paths
    assert "sso/usso/apikey" not in paths


def test_resource_paths_include_feature_gated_paths() -> None:
    """Workspace, agents, and api_key flags add their catalog paths."""
    from apps.tenant.config import TenantConfig
    from apps.tenant.scope_catalog import bootstrap

    paths = bootstrap.resource_paths_for_tenant(
        TenantConfig(
            workspace={"enabled": True},
            agents={"enabled": True},
            integration={"api_key": {"enabled": True}},
        )
    )
    assert "sso/usso/user" in paths
    assert "sso/usso/workspace" in paths
    assert "sso/usso/workspace_invitation" in paths
    assert "sso/usso/member" in paths
    assert "sso/user" not in paths
    assert "sso/usso/agent" in paths
    assert "sso/usso/apikey" in paths


def test_build_usso_catalog_items_includes_manage_and_admin_user_scopes() -> None:
    """User CRUD (manage) and impersonation (admin) both appear in catalog."""
    from apps.tenant.config import TenantConfig
    from apps.tenant.scope_catalog import bootstrap

    items = bootstrap.build_usso_catalog_items(TenantConfig())
    by_scope = {item.scope: item for item in items}
    assert "manage:sso/usso/user" in by_scope
    assert "admin:sso/usso/user" in by_scope
    assert "read:sso/usso/user" in by_scope
    assert "manage:sso/usso/member" in by_scope
    assert "manage:sso/user" not in by_scope
    assert by_scope["manage:sso/usso/user"].label_fa == "مدیریت کاربران"
    assert by_scope["admin:sso/usso/user"].label_fa == "ورود به حساب کاربران"
    assert by_scope["manage:sso/usso/member"].label_fa == "مدیریت اعضای فضای کاری"


@pytest.mark.asyncio
async def test_register_usso_scope_catalog_syncs_each_tenant() -> None:
    """Startup seed calls sync_service_scopes once per non-deleted tenant."""
    from apps.tenant.scope_catalog import bootstrap

    tenants = [
        SimpleNamespace(uid="t1", config=SimpleNamespace()),
        SimpleNamespace(uid="t2", config=SimpleNamespace()),
    ]
    find_chain = mock.MagicMock()
    find_chain.to_list = mock.AsyncMock(return_value=tenants)
    items = [schemas.ScopeCatalogItemIn(scope="manage:sso/role")]

    with (
        mock.patch(
            "apps.tenant.scope_catalog.bootstrap.Tenant.find",
            return_value=find_chain,
        ),
        mock.patch(
            "apps.tenant.scope_catalog.bootstrap.build_usso_catalog_items",
            return_value=items,
        ) as build_mock,
        mock.patch(
            "apps.tenant.scope_catalog.bootstrap.services.sync_service_scopes",
            new_callable=mock.AsyncMock,
        ) as sync_mock,
    ):
        await bootstrap.register_usso_scope_catalog()

    assert build_mock.call_count == 2
    assert sync_mock.await_count == 2
    sync_mock.assert_any_await(
        tenant_id="t1",
        service=bootstrap.SSO_CATALOG_SERVICE,
        items=items,
    )
    sync_mock.assert_any_await(
        tenant_id="t2",
        service=bootstrap.SSO_CATALOG_SERVICE,
        items=items,
    )
