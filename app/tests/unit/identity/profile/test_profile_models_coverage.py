"""Unit coverage for profile model helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from apps.identity.profile.models import Profile
from apps.identity.user.models import User


@pytest.mark.asyncio
async def test_get_by_user_id_returns_existing_profile_and_loads_identifiers() -> None:
    profile = SimpleNamespace(get_identifiers=AsyncMock())
    with patch.object(Profile, "find_one", new=AsyncMock(return_value=profile)) as find:
        result = await Profile.get_by_user_id(tenant_id="tenant-1", user_id="user-1")
    assert result is profile
    find.assert_awaited_once_with({"user_id": "user-1", "tenant_id": "tenant-1"})
    profile.get_identifiers.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_by_user_id_creates_and_saves_missing_profile() -> None:
    with (
        patch.object(Profile, "find_one", new=AsyncMock(return_value=None)),
        patch.object(Profile, "get_pymongo_collection"),
        patch.object(Profile, "save", new=AsyncMock()) as save,
        patch.object(Profile, "get_identifiers", new=AsyncMock()) as identifiers,
    ):
        profile = await Profile.get_by_user_id(tenant_id="tenant-1", user_id="user-1")
    assert profile.tenant_id == "tenant-1"
    assert profile.user_id == "user-1"
    assert profile.uid == "user-1"
    save.assert_awaited_once_with()
    identifiers.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_get_identifiers_loads_uncached_user_identifiers() -> None:
    profile = Profile.model_construct(
        tenant_id="tenant-1", user_id="user-1", uid="user-1"
    )
    identifiers = [
        SimpleNamespace(type="email", identifier="ada@example.com"),
        SimpleNamespace(type="phone", identifier="+989121234567"),
    ]
    user = SimpleNamespace(get_identifiers=AsyncMock(return_value=identifiers))
    with patch.object(User, "get_item", new=AsyncMock(return_value=user)) as get_user:
        result = await profile.get_identifiers()
    assert result is profile
    assert profile._identifiers == {
        "email": "ada@example.com",
        "phone": "+989121234567",
    }
    get_user.assert_awaited_once_with(uid="user-1", tenant_id="tenant-1")
    user.get_identifiers.assert_awaited_once_with(not_cached=True)


@pytest.mark.asyncio
async def test_get_user_custom_claims_returns_user_claims() -> None:
    profile = Profile.model_construct(
        tenant_id="tenant-1", user_id="user-1", uid="user-1"
    )
    user = SimpleNamespace(custom_claims={"locale": "fa"})
    with patch.object(User, "get_item", new=AsyncMock(return_value=user)) as get_user:
        assert await profile.get_user_custom_claims() == {"locale": "fa"}
    get_user.assert_awaited_once_with(uid="user-1", tenant_id="tenant-1")
