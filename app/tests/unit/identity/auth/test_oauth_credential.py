"""Unit tests for create_oauth_credential profile persistence."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.auth.services.oauth import (
    create_oauth_credential,
    merge_oauth_into_profile,
)


def test_merge_oauth_does_not_override_existing_fields() -> None:
    merged = merge_oauth_into_profile(
        existing={
            "first_name": "مهدی",
            "last_name": "کیانی",
            "avatar_url": "https://media.uln.me/me.png",
            "meta_data": {"personal_prompts": {"a": "1"}, "oauth": {"provider": "old"}},
        },
        incoming={
            "first_name": "Ada",
            "last_name": "Lovelace",
            "avatar_url": "https://cdn.example/x.png",
            "meta_data": {"oauth": {"provider": "google", "sub": "g-1"}},
        },
    )
    assert merged["first_name"] == "مهدی"
    assert merged["last_name"] == "کیانی"
    assert merged["avatar_url"] == "https://media.uln.me/me.png"
    assert merged["meta_data"]["personal_prompts"] == {"a": "1"}
    assert merged["meta_data"]["oauth"]["provider"] == "google"
    assert merged["meta_data"]["oauth"]["sub"] == "g-1"


def test_merge_oauth_fills_blank_fields_only() -> None:
    merged = merge_oauth_into_profile(
        existing={"first_name": "", "last_name": None, "meta_data": {}},
        incoming={
            "first_name": "Ada",
            "last_name": "Lovelace",
            "meta_data": {"oauth": {"provider": "telegram"}},
        },
    )
    assert merged["first_name"] == "Ada"
    assert merged["last_name"] == "Lovelace"
    assert merged["meta_data"]["oauth"]["provider"] == "telegram"


@pytest.mark.asyncio
async def test_create_oauth_credential_creates_profile() -> None:
    """New OAuth users get a profile seeded from userinfo."""
    tenant = MagicMock(uid="t1")
    user = MagicMock(uid="u1")
    profile = MagicMock(profile_data=None)
    profile.save = AsyncMock()

    profile_cls = MagicMock(return_value=profile)
    profile_cls.get_by_user_id = AsyncMock(return_value=None)

    with (
        patch(
            "apps.identity.auth.services.oauth.find_or_create_user",
            new_callable=AsyncMock,
            return_value=(user, True),
        ),
        patch(
            "apps.identity.auth.services.oauth.Profile",
            profile_cls,
        ),
    ):
        result = await create_oauth_credential(
            tenant=tenant,
            provider="google",
            email="user@example.com",
            jwks_uri="https://idp/jwks",
            userinfo={
                "sub": "provider-user-1",
                "name": "User",
                "given_name": "Ada",
                "bank_accounts": [{"iban": "attacker", "verified_at": "now"}],
            },
        )
    assert result is user
    profile_cls.assert_called_once()
    assert profile.profile_data["first_name"] == "Ada"
    assert profile.profile_data["meta_data"]["oauth"]["name"] == "User"
    assert "bank_accounts" not in profile.profile_data
    profile.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_oauth_credential_existing_user_adds_credential() -> None:
    """Existing users get an additional OAuth credential attached."""
    tenant = MagicMock(uid="t1")
    user = MagicMock(uid="u1")
    profile = MagicMock(profile_data={"meta_data": {"source": "existing"}})
    profile.save = AsyncMock()

    with (
        patch(
            "apps.identity.auth.services.oauth.find_or_create_user",
            new_callable=AsyncMock,
            return_value=(user, False),
        ),
        patch(
            "apps.identity.auth.services.oauth.add_credential",
            new_callable=AsyncMock,
        ) as add_credential,
        patch(
            "apps.identity.auth.services.oauth.Profile.get_by_user_id",
            new_callable=AsyncMock,
            return_value=profile,
        ),
    ):
        result = await create_oauth_credential(
            tenant=tenant,
            provider="google",
            email="user@example.com",
            jwks_uri="https://idp/jwks",
            userinfo={"name": "User"},
        )
    assert result is user
    add_credential.assert_awaited_once()
    assert profile.profile_data["meta_data"]["source"] == "existing"
    assert profile.profile_data["meta_data"]["oauth"]["name"] == "User"
    profile.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_oauth_credential_keeps_existing_profile_fields() -> None:
    """Re-login via OAuth must not overwrite user-edited profile fields."""
    tenant = MagicMock(uid="t1")
    user = MagicMock(uid="u1")
    profile = MagicMock(
        profile_data={
            "first_name": "مهدی",
            "last_name": "کیانی",
            "avatar_url": "https://media.uln.me/me.png",
            "meta_data": {"personal_prompts": {"tone": "formal"}},
        }
    )
    profile.save = AsyncMock()

    with (
        patch(
            "apps.identity.auth.services.oauth.find_or_create_user",
            new_callable=AsyncMock,
            return_value=(user, False),
        ),
        patch(
            "apps.identity.auth.services.oauth.add_credential",
            new_callable=AsyncMock,
        ),
        patch(
            "apps.identity.auth.services.oauth.Profile.get_by_user_id",
            new_callable=AsyncMock,
            return_value=profile,
        ),
    ):
        await create_oauth_credential(
            tenant=tenant,
            provider="google",
            email="user@example.com",
            jwks_uri="https://idp/jwks",
            userinfo={
                "given_name": "Ada",
                "family_name": "Lovelace",
                "picture": "https://cdn.example/x.png",
                "name": "Ada Lovelace",
                "sub": "g-1",
            },
        )

    assert profile.profile_data["first_name"] == "مهدی"
    assert profile.profile_data["last_name"] == "کیانی"
    assert profile.profile_data["avatar_url"] == "https://media.uln.me/me.png"
    assert profile.profile_data["meta_data"]["personal_prompts"]["tone"] == "formal"
    assert profile.profile_data["meta_data"]["oauth"]["provider"] == "google"
