"""Focused route coverage for tenant management."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.routes import AbstractBaseRouter

from apps.tenant import config, routes, schemas
from server.exceptions import BadRequestError


def test_deep_merge_dicts_nested() -> None:
    merged = schemas.deep_merge_dicts(
        {"registration": {"approval_mode": "identifier", "is_allowed": True}},
        {"registration": {"approval_mode": "additional"}},
    )
    assert merged["registration"]["approval_mode"] == "additional"
    assert merged["registration"]["is_allowed"] is True


@pytest.mark.asyncio
async def test_get_user_requires_main_tenant() -> None:
    router = routes.TenantRouter()
    with (
        patch.object(
            routes.models.Tenant, "get_from_domain", new=AsyncMock(return_value=None)
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await router.get_user(MagicMock())
    assert exc.value.error_code == "tenant_not_found"


@pytest.mark.asyncio
async def test_get_user_calls_main_tenant_access_auth() -> None:
    router = routes.TenantRouter()
    request = MagicMock()
    payload = object()
    access_auth = MagicMock(return_value=payload)
    tenant = SimpleNamespace(access_auth=access_auth)
    with patch.object(
        routes.models.Tenant,
        "get_from_domain",
        new=AsyncMock(return_value=tenant),
    ):
        result = await router.get_user(request)
    assert result is payload
    access_auth.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_create_item_adds_generated_secrets_and_owner() -> None:
    router = routes.TenantRouter()
    request = MagicMock()
    data = schemas.TenantCreateSchema(name="Test Tenant", domains=["tenant.test"])
    secret = object()
    created = object()
    with (
        patch.object(router, "get_user_id", new=AsyncMock(return_value="owner-1")),
        patch.object(
            routes.secrets.TenantSecrets,
            "generate_random_tenant_secrets",
            return_value=secret,
        ),
        patch.object(
            AbstractBaseRouter, "create_item", new=AsyncMock(return_value=created)
        ) as base_create,
    ):
        result = await router.create_item(request, data)

    assert result is created
    payload = base_create.await_args.kwargs["data"]
    assert payload["secrets"] is secret
    assert payload["user_id"] == "owner-1"


@pytest.mark.asyncio
async def test_create_item_logs_and_returns_none_on_failure() -> None:
    router = routes.TenantRouter()
    data = schemas.TenantCreateSchema(name="Test Tenant", domains=["tenant.test"])
    with (
        patch.object(router, "get_user_id", new=AsyncMock(return_value="owner-1")),
        patch.object(
            routes.secrets.TenantSecrets,
            "generate_random_tenant_secrets",
            return_value=object(),
        ),
        patch.object(
            AbstractBaseRouter,
            "create_item",
            new=AsyncMock(side_effect=RuntimeError("database down")),
        ),
        patch.object(routes.logger, "exception") as log_exception,
    ):
        assert await router.create_item(MagicMock(), data) is None
    log_exception.assert_called_once_with("Error creating tenant")


@pytest.mark.asyncio
async def test_update_item_excludes_unset_fields() -> None:
    router = routes.TenantRouter()
    request = MagicMock()
    updated = object()
    with patch.object(
        AbstractBaseRouter, "update_item", new=AsyncMock(return_value=updated)
    ) as base_update:
        result = await router.update_item(
            request, "tenant-1", schemas.TenantUpdateSchema(name="Renamed")
        )
    assert result is updated
    base_update.assert_awaited_once_with(request, "tenant-1", {"name": "Renamed"})


@pytest.mark.asyncio
async def test_update_item_merges_partial_config() -> None:
    router = routes.TenantRouter()
    item = SimpleNamespace(config=config.TenantConfig())
    with (
        patch.object(router, "get_user_id", new=AsyncMock(return_value="owner-1")),
        patch.object(router, "get_item", new=AsyncMock(return_value=item)),
        patch.object(
            AbstractBaseRouter, "update_item", new=AsyncMock(return_value=item)
        ) as base_update,
    ):
        await router.update_item(
            MagicMock(),
            "tenant-1",
            schemas.TenantUpdateSchema(
                config={
                    "registration": {"approval_mode": "additional"},
                    "workspace": {"personal_workspace_active_by_default": False},
                }
            ),
        )
    payload = base_update.await_args.args[2]
    cfg = payload["config"]
    assert cfg.registration.approval_mode == config.ApprovalMode.ADDITIONAL
    assert cfg.workspace.personal_workspace_active_by_default is False
    assert cfg.workspace.enabled is True


def _public_tenant(
    name: str = "Tenant", telegram: object | None = None
) -> SimpleNamespace:
    tenant_config = config.TenantConfig()
    return SimpleNamespace(
        name=name,
        config=tenant_config,
        secrets=SimpleNamespace(
            oauth_secrets={} if telegram is None else {"telegram": telegram}
        ),
    )


@pytest.mark.asyncio
async def test_get_config_prefers_request_hostname_and_telegram_client() -> None:
    router = routes.TenantRouter()
    request = MagicMock()
    request.url.hostname = "custom.test"
    tenant = _public_tenant(telegram=SimpleNamespace(client_id="telegram-client"))
    lookup = AsyncMock(return_value=tenant)
    with patch.object(routes.models.Tenant, "get_from_domain", new=lookup):
        result = await router.get_config(request)
    assert result.name == "Tenant"
    assert result.telegram_client_id == "telegram-client"
    lookup.assert_awaited_once_with("custom.test")


@pytest.mark.asyncio
async def test_get_config_falls_back_to_root_then_first_tenant() -> None:
    router = routes.TenantRouter()
    request = MagicMock()
    request.url.hostname = "missing.test"
    tenant = _public_tenant("Fallback")
    lookup = AsyncMock(side_effect=[None, None])
    with (
        patch.object(routes.models.Tenant, "get_from_domain", new=lookup),
        patch.object(
            routes.models.Tenant, "find_one", new=AsyncMock(return_value=tenant)
        ) as find_one,
    ):
        result = await router.get_config(request)
    assert result.name == "Fallback"
    assert result.telegram_client_id is None
    assert lookup.await_count == 2
    find_one.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_get_config_raises_when_no_tenant_exists() -> None:
    router = routes.TenantRouter()
    request = MagicMock()
    request.url.hostname = None
    with (
        patch.object(
            routes.models.Tenant, "get_from_domain", new=AsyncMock(return_value=None)
        ),
        patch.object(
            routes.models.Tenant, "find_one", new=AsyncMock(return_value=None)
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await router.get_config(request)
    assert exc.value.error_code == "tenant_not_found"
