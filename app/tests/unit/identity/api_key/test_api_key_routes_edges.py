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
