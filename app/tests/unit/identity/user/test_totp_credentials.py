"""Unit tests for TOTP credential registration helpers."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from usso import UserData

from apps.identity.auth.enums import AuthIdentifier
from apps.identity.user import credential_services as creds
from server.exceptions import BadRequestError, NotFoundError


@pytest.mark.asyncio
async def test_register_random_totp_challenge_requires_user() -> None:
    """Missing user raises NotFoundError."""
    tenant = MagicMock()
    user_data = UserData(user_id="u1", tenant_id="t1")
    with (
        patch.object(
            creds.models.User, "get_item", new_callable=AsyncMock, return_value=None
        ),
        pytest.raises(NotFoundError),
    ):
        await creds.register_random_totp_challenge(tenant, user_data)


@pytest.mark.asyncio
async def test_register_random_totp_challenge_success() -> None:
    """TOTP registration returns secret, QR, and provisioning URI."""
    tenant = MagicMock()
    tenant.name = "Acme"
    tenant.primary_domain = "acme.test"
    user_data = UserData(user_id="u1", tenant_id="t1")

    user = MagicMock()
    user.user_id = "u1"
    user.tenant_id = "t1"
    email = MagicMock(type=AuthIdentifier.EMAIL, identifier="u@acme.test")
    user.get_identifiers = AsyncMock(return_value=[email])

    with (
        patch.object(
            creds.models.User, "get_item", new_callable=AsyncMock, return_value=user
        ),
        patch.object(
            creds.models.Credential, "create_item", new_callable=AsyncMock
        ) as create_item,
    ):
        result = await creds.register_random_totp_challenge(tenant, user_data)

    assert result["secret"]
    assert result["qr_code"]
    assert result["provisioning_uri"].startswith("otpauth://totp/")
    create_item.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_totp_challenge_success_and_errors() -> None:
    """Verify activates credential; missing/invalid codes raise BadRequestError."""
    tenant = MagicMock()
    user = MagicMock(user_id="u1", tenant_id="t1")
    data = MagicMock()
    data.secret = "123456"
    data.expires_at = None

    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=None)
    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        pytest.raises(BadRequestError) as missing,
    ):
        await creds.verify_totp_challenge(tenant, user, data)
    assert missing.value.error_code == "totp_challenge_not_found"

    cred = MagicMock()
    cred.secret = "BASE32SECRET"
    cred.save = AsyncMock(return_value=cred)
    query.first_or_none = AsyncMock(return_value=cred)

    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        patch.object(creds.services, "validate_totp", return_value=False),
        pytest.raises(BadRequestError) as invalid,
    ):
        await creds.verify_totp_challenge(tenant, user, data)
    assert invalid.value.error_code == "totp_challenge_not_valid"

    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        patch.object(creds.services, "validate_totp", return_value=True),
    ):
        result = await creds.verify_totp_challenge(tenant, user, data)
    assert result is cred
    assert cred.is_active is True
    cred.save.assert_awaited_once()
