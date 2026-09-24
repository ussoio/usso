"""Failure and success edges for agent-management routes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.agent import routes, schemas
from server.exceptions import BadRequestError, UnauthorizedError


def _request(authorization: str | None = None) -> MagicMock:
    request = MagicMock()
    request.headers = {} if authorization is None else {"Authorization": authorization}
    return request


def _router(*, enabled: bool = True) -> routes.AgentRouter:
    router = routes.AgentRouter()
    router.get_tenant = AsyncMock(
        return_value=SimpleNamespace(
            uid="tenant",
            config=SimpleNamespace(agents=SimpleNamespace(enabled=enabled)),
        )
    )
    router.get_user = AsyncMock(
        return_value=SimpleNamespace(uid="user", tenant_id="tenant")
    )
    return router


@pytest.mark.asyncio
async def test_create_agent_rejects_disabled_feature_and_missing_user() -> None:
    data = schemas.AgentCreateSchema(name="agent", scopes=[], user_id="user")
    router = _router(enabled=False)
    with (
        patch.object(routes, "require_secure_token"),
        pytest.raises(BadRequestError) as disabled,
    ):
        await router.create_item(_request(), data)
    assert disabled.value.error_code == "agents_not_enabled"

    router = _router()
    with (
        patch.object(routes, "require_secure_token"),
        patch(
            "apps.identity.user.models.User.get_item",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError) as missing,
    ):
        await router.create_item(_request(), data)
    assert missing.value.error_code == "user_not_found"


@pytest.mark.asyncio
async def test_update_agent_rejects_missing_caller_user() -> None:
    router = _router()
    router.get_item = AsyncMock(
        return_value=SimpleNamespace(user_id="user", workspace_id=None)
    )
    with (
        patch.object(routes, "require_secure_token"),
        patch(
            "apps.identity.user.models.User.get_item",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError) as missing,
    ):
        await router.update_item(
            _request(), "agent", schemas.AgentUpdateSchema(scopes=["read:x"])
        )
    assert missing.value.error_code == "user_not_found"


@pytest.mark.asyncio
async def test_agent_scopes_requires_bearer_and_returns_public_schema() -> None:
    router = _router()
    with pytest.raises(UnauthorizedError) as missing:
        await router.agent_scopes(_request())
    assert missing.value.error_code == "jwt_required"

    agent = schemas.AgentResponseSchema.model_construct(
        uid="agent",
        tenant_id="tenant",
        name="robot",
        scopes=["read:x"],
        user_id="user",
    )
    with patch.object(
        routes.services,
        "agent_auth",
        new=AsyncMock(return_value=(agent, object())),
    ):
        response = await router.agent_scopes(_request("Bearer signed"))
    assert response.uid == "agent"
