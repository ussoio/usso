"""Spend-limit support for API keys (CEO policy 2026-10-08)."""

import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from apps.access_control import workspace as workspace_pkg
from apps.identity.api_key import routes, schemas, services
from server.exceptions import ForbiddenError


def _key(**overrides: object) -> SimpleNamespace:
    values = {
        "uid": "key-1",
        "spend_limit": None,
        "spend_usage": 0.0,
        "tenant_id": "tenant-1",
        "workspace_id": None,
        "scopes": [],
        "user_id": "user-1",
        "created_by": None,
        "created_at": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_schemas_accept_and_validate_spend_limit() -> None:
    assert schemas.APIKeyCreateSchema().spend_limit is None
    assert schemas.APIKeyCreateSchema(spend_limit=5).spend_limit == 5
    assert schemas.APIKeyUpdateSchema(spend_limit=0).spend_limit == 0
    with pytest.raises(ValidationError):
        schemas.APIKeyCreateSchema(spend_limit=-1)
    with pytest.raises(ValidationError):
        schemas.APIKeyUpdateSchema(spend_limit=-1)


def test_response_schema_exposes_spend_fields() -> None:
    assert {"spend_limit", "spend_usage"} <= set(
        schemas.APIKeyResponseSchema.model_fields
    )
    assert schemas.APIKeyResponseSchema.model_fields[
        "spend_usage"
    ].default == pytest.approx(0.0)


def test_update_schema_distinguishes_unset_from_null() -> None:
    assert schemas.APIKeyUpdateSchema().model_dump(exclude_unset=True) == {}
    cleared = schemas.APIKeyUpdateSchema(spend_limit=None)
    assert cleared.model_dump(exclude_unset=True) == {"spend_limit": None}


@pytest.mark.parametrize(("limit", "usage"), [(None, 999.0), (10.0, 0.0), (10.0, 9.99)])
def test_spend_limit_not_reached_passes(limit: float | None, usage: float) -> None:
    services.enforce_api_key_spend_limit(_key(spend_limit=limit, spend_usage=usage))


@pytest.mark.parametrize(("limit", "usage"), [(10.0, 10.0), (10.0, 11.5), (0.0, 0.0)])
def test_spend_limit_reached_is_rejected(limit: float, usage: float) -> None:
    with pytest.raises(ForbiddenError) as exc:
        services.enforce_api_key_spend_limit(_key(spend_limit=limit, spend_usage=usage))
    assert exc.value.error_code == "api_key_spend_limit_exceeded"


def test_user_data_carries_spend_claims() -> None:
    data = services.api_key_to_user_data(_key(spend_limit=10.0, spend_usage=2.5))
    assert data.claims["spend_limit"] == pytest.approx(10.0)
    assert data.claims["spend_usage"] == pytest.approx(2.5)


def _query(items: list[object]) -> MagicMock:
    query = MagicMock()
    query.to_list = AsyncMock(return_value=items)
    return query


@pytest.mark.asyncio
async def test_verify_api_key_rejects_exhausted_key() -> None:
    db_key = _key(
        hashed_key="h",
        is_active=True,
        revoked=None,
        expires_at=None,
        spend_limit=1.0,
        spend_usage=1.0,
    )
    uid = services.generate_api_key()["api_key"]
    with (
        patch.object(services.APIKey, "get_query", return_value=_query([db_key])),
        patch.object(
            services.PasswordHasherService, "verify_password", return_value=True
        ),
        pytest.raises(ForbiddenError) as exc,
    ):
        await services.verify_api_key(uid)
    assert exc.value.error_code == "api_key_spend_limit_exceeded"


@pytest.mark.asyncio
async def test_get_api_key_data_rechecks_spend_despite_cached_credential() -> None:
    """The credential cache must not let an exhausted key keep authenticating."""
    db_key = _key(
        is_active=True,
        revoked=None,
        expires_at=None,
        ip_whitelist=[],
        rate_limit=None,
        spend_limit=1.0,
        spend_usage=3.0,
    )
    with (
        patch.object(
            services, "_verify_api_key_cached", new=AsyncMock(return_value=("u", "k"))
        ),
        patch.object(services.APIKey, "get_query", return_value=_query([db_key])),
        pytest.raises(ForbiddenError) as exc,
    ):
        await services.get_api_key_data("uak-x.y", tenant_id="tenant-1")
    assert exc.value.error_code == "api_key_spend_limit_exceeded"


@pytest.mark.asyncio
async def test_record_api_key_spend_increments_and_invalidates() -> None:
    collection = SimpleNamespace(update_one=AsyncMock())
    with (
        patch.object(
            services.APIKey, "get_pymongo_collection", return_value=collection
        ),
        patch.object(services, "invalidate_api_key_cache", new=AsyncMock()) as inval,
    ):
        await services.record_api_key_spend("key-1", 2.5)
    collection.update_one.assert_awaited_once_with(
        {"uid": "key-1", "is_deleted": False}, {"$inc": {"spend_usage": 2.5}}
    )
    inval.assert_awaited_once_with(uid="key-1")


@pytest.mark.asyncio
async def test_update_item_sets_only_sent_fields_and_invalidates() -> None:
    router = routes.api_key_router
    item = SimpleNamespace(
        uid="key-1",
        spend_limit=None,
        name="old",
        save=AsyncMock(),
        model_dump=lambda: {
            "uid": "key-1",
            "tenant_id": "t",
            "api_key_pattern": "uak-***",
            "name": "old",
            "spend_limit": 7.0,
        },
    )
    with (
        patch.object(routes, "require_secure_token"),
        patch.object(
            router, "get_tenant", new=AsyncMock(return_value=SimpleNamespace(uid="t"))
        ),
        patch.object(
            router, "get_user", new=AsyncMock(return_value=SimpleNamespace(uid="u"))
        ),
        patch.object(router, "get_item", new=AsyncMock(return_value=item)) as get,
        patch.object(routes.services, "invalidate_api_key_cache", new=AsyncMock()),
    ):
        out = await router.update_item(
            MagicMock(), "key-1", schemas.APIKeyUpdateSchema(spend_limit=7.0)
        )
    get.assert_awaited_once_with(uid="key-1", user_id="u", tenant_id="t")
    assert item.spend_limit == pytest.approx(7.0)
    assert item.name == "old"
    item.save.assert_awaited_once()
    assert out.spend_limit == pytest.approx(7.0)


def test_workspace_creation_grants_no_signup_credits() -> None:
    """Signup credits belong to the user identity, never to a workspace."""
    pattern = re.compile(r"credit|bonus|enrollment|saas", re.IGNORECASE)
    root = Path(workspace_pkg.__file__).parent
    hits = [
        f"{path.name}:{n}: {line.strip()}"
        for path in root.glob("*.py")
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if pattern.search(line)
    ]
    assert hits == []
