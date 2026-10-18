"""Edge coverage for API-key route response and caller validation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.api_key import routes, schemas
from server.exceptions import UnauthorizedError


def test_api_key_response_adds_client_id() -> None:
    expected = object()
    schema = MagicMock()
    schema.model_validate.return_value = expected
    router = SimpleNamespace(schema=schema)
    item = SimpleNamespace(
        uid="key",
        model_dump=MagicMock(return_value={"uid": "key"}),
    )
    assert routes.APIKeyRouter._to_response(router, item) is expected
    assert schema.model_validate.call_args.args[0]["client_id"] == "key"


@pytest.mark.asyncio
async def test_api_key_create_rejects_missing_caller_user() -> None:
    router = routes.api_key_router
    data = schemas.APIKeyCreateSchema(name="key", scopes=[], user_id="user")
    with (
        patch.object(routes, "require_secure_token"),
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=SimpleNamespace(uid="tenant")),
        ),
        patch.object(
            router,
            "get_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user")),
        ),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(UnauthorizedError) as missing,
    ):
        await router.create_item(MagicMock(), data)
    assert missing.value.error_code == "user_not_found"


def _tenant(self_service: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant",
        config=SimpleNamespace(
            integration=SimpleNamespace(
                api_key=SimpleNamespace(self_service_scopes=self_service)
            )
        ),
    )


@pytest.mark.asyncio
async def test_api_key_grantable_scopes_returns_ceiling_with_self_service() -> None:
    router = routes.api_key_router
    caller_user = SimpleNamespace(
        uid="user",
        tenant_id="tenant",
        get_effective_scopes_for_api=AsyncMock(return_value=["read:finance/*/*"]),
    )
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(["create:ai/ai-toolkit/*"])),
        ),
        patch.object(
            router,
            "get_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user")),
        ),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=caller_user)),
        patch(
            "apps.identity.service_account.User.get_item",
            new=AsyncMock(return_value=caller_user),
        ),
    ):
        result = await router.grantable_scopes(MagicMock())
    assert result.scopes == ["read:finance/*/*", "create:ai/ai-toolkit/*"]
    assert result.self_service_scopes == ["create:ai/ai-toolkit/*"]


def test_api_key_scopes_route_is_not_shadowed_by_uid_route() -> None:
    paths = [
        (route.path, sorted(route.methods))
        for route in routes.router.routes
        if "GET" in getattr(route, "methods", set())
    ]
    scopes_index = next(i for i, (p, _) in enumerate(paths) if p.endswith("/scopes"))
    uid_indexes = [i for i, (p, _) in enumerate(paths) if p.endswith("{uid}")]
    assert all(scopes_index < i for i in uid_indexes)


@pytest.mark.asyncio
async def test_api_key_create_allows_self_service_scope_for_user_without_roles() -> (
    None
):
    router = routes.api_key_router
    caller = SimpleNamespace(uid="user", user_id="user", workspace_id=None, scopes=[])
    caller_user = SimpleNamespace(
        uid="user",
        tenant_id="tenant",
        get_effective_scopes_for_api=AsyncMock(return_value=[]),
    )
    data = schemas.APIKeyCreateSchema(name="key", scopes=["create:ai/ai-toolkit/*"])
    saved = MagicMock()
    saved.model_dump.return_value = {
        "uid": "00000000-0000-0000-0000-000000000001",
        "tenant_id": "tenant",
        "user_id": "user",
        "api_key_pattern": "uak-xxxx****",
        "scopes": ["create:ai/ai-toolkit/*"],
    }
    saved.uid = "00000000-0000-0000-0000-000000000001"
    model_instance = MagicMock()
    model_instance.save = AsyncMock(return_value=saved)
    with (
        patch.object(routes, "require_secure_token"),
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(["create:ai/ai-toolkit/*"])),
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=caller)),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=caller_user)),
        patch(
            "apps.identity.service_account.User.get_item",
            new=AsyncMock(return_value=caller_user),
        ),
        patch.object(routes.models, "APIKey", return_value=model_instance) as api_key,
    ):
        result = await router.create_item(MagicMock(), data)
    assert api_key.call_args.kwargs["scopes"] == ["create:ai/ai-toolkit/*"]
    assert result.api_key.startswith("uak-")
