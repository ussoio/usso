"""Focused unit coverage for profile route handlers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from apps.identity.profile import routes, schemas
from utils.usso_routes import AbstractTenantUSSORouter


@pytest.mark.asyncio
async def test_create_update_and_mine_delegate_to_base_router() -> None:
    router = routes.ProfileRouter()
    request = MagicMock()
    uid = uuid4()
    create_data = schemas.ProfileCreateSchema(
        user_id="user-1",
        profile_data=schemas.ProfileDataCreateSchema(first_name="Ada"),
    )
    update_data = schemas.ProfileUpdateSchema(profile_data={"first_name": "Grace"})
    with (
        patch.object(
            AbstractTenantUSSORouter,
            "create_item",
            new=AsyncMock(return_value="created"),
        ) as create,
        patch.object(
            AbstractTenantUSSORouter,
            "update_item",
            new=AsyncMock(return_value="updated"),
        ) as update,
        patch.object(
            AbstractTenantUSSORouter,
            "mine_items",
            new=AsyncMock(return_value="mine"),
        ) as mine,
    ):
        assert await router.create_item(request, create_data) == "created"
        assert await router.update_item(request, uid, update_data) == "updated"
        assert await router.mine_items(request) == "mine"
    create.assert_awaited_once_with(request, create_data.model_dump())
    update.assert_awaited_once_with(
        request, uid, update_data.model_dump(exclude_unset=True)
    )
    mine.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_update_mine_uses_authenticated_user_uid() -> None:
    router = routes.ProfileRouter()
    request = MagicMock()
    uid = uuid4()
    data = schemas.ProfileUpdateSchema(meta_data={"theme": "dark"})
    get_user = AsyncMock(return_value=SimpleNamespace(uid=uid))
    update_item = AsyncMock(return_value="updated")
    with (
        patch.object(router, "get_user", new=get_user),
        patch.object(router, "update_item", new=update_item),
    ):
        assert await router.update_mine_items(request, data) == "updated"
    update_item.assert_awaited_once_with(request, uid, data)


def test_profile_data_ignores_legacy_ice_fields() -> None:
    data = schemas.ProfileDataCreateSchema(
        first_name="Ada",
        father_name="Byron",
        personnel_no="1001",
        bank_accounts=[{"iban": "IR00"}],
    )
    dumped = data.model_dump()
    assert dumped["first_name"] == "Ada"
    assert "father_name" not in dumped
    assert "personnel_no" not in dumped
    assert "bank_accounts" not in dumped


def test_profile_update_forbids_legacy_ice_fields() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        schemas.ProfileDataUpdateSchema(first_name="Ada", father_name="Byron")
