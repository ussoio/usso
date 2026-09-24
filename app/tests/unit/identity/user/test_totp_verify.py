"""Unit tests for TOTP challenge verification and WebAuthn helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.user import credential_services as creds
from apps.identity.user import schemas
from server.exceptions import BadRequestError


@pytest.mark.asyncio
async def test_verify_totp_challenge_missing_raises() -> None:
    """Missing inactive TOTP challenge raises BadRequestError."""
    tenant = MagicMock()
    user = MagicMock()
    user.user_id = "u1"
    user.tenant_id = "t1"
    data = schemas.TOTPCreateSchema(secret="123456")

    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=None)
    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        pytest.raises(BadRequestError) as exc,
    ):
        await creds.verify_totp_challenge(tenant, user, data)
    assert exc.value.error_code == "totp_challenge_not_found"


@pytest.mark.asyncio
async def test_verify_totp_challenge_invalid_code() -> None:
    """Wrong TOTP code rejects the challenge."""
    tenant = MagicMock()
    user = MagicMock()
    user.user_id = "u1"
    user.tenant_id = "t1"
    data = schemas.TOTPCreateSchema(secret="000000")
    cred = MagicMock()
    cred.secret = "BASE32SECRET"
    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=cred)

    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        patch.object(creds.services, "validate_totp", return_value=False),
        pytest.raises(BadRequestError) as exc,
    ):
        await creds.verify_totp_challenge(tenant, user, data)
    assert exc.value.error_code == "totp_challenge_not_valid"


@pytest.mark.asyncio
async def test_verify_totp_challenge_success() -> None:
    """Valid code activates and saves the TOTP credential."""
    tenant = MagicMock()
    user = MagicMock()
    user.user_id = "u1"
    user.tenant_id = "t1"
    data = schemas.TOTPCreateSchema(
        secret="123456",
        expires_at=None,
    )
    cred = MagicMock()
    cred.secret = "BASE32SECRET"
    cred.save = AsyncMock(return_value=cred)
    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=cred)

    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        patch.object(creds.services, "validate_totp", return_value=True),
    ):
        result = await creds.verify_totp_challenge(tenant, user, data)

    assert result is cred
    assert cred.is_active is True
    cred.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_webauthn_credentials_returns_ids() -> None:
    """WebAuthn credentials return PublicKeyCredentialDescriptor list."""
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )

    user = MagicMock()
    cred = MagicMock()
    # valid base64url payload for credential id
    cred.meta_data = {"credential_id": "Y3JlZC0x"}
    user.get_credentials = AsyncMock(return_value=[cred])
    result = await creds.get_webauthn_credentials(user)
    assert result is not None
    assert len(result) == 1
    assert isinstance(result[0], PublicKeyCredentialDescriptor)
    assert result[0].type == PublicKeyCredentialType.PUBLIC_KEY
    assert result[0].id == b"cred-1"


@pytest.mark.asyncio
async def test_get_webauthn_credentials_none_when_empty() -> None:
    """No credentials yields None."""
    user = MagicMock()
    user.get_credentials = AsyncMock(return_value=[])
    assert await creds.get_webauthn_credentials(user) is None


@pytest.mark.asyncio
async def test_generate_authentication_challenge_stores_redis() -> None:
    """Authentication challenge is stored in Redis and returned as dict."""
    tenant = MagicMock()
    tenant.primary_domain = "sso.example.test"
    options = SimpleNamespace(challenge=b"challenge-bytes")

    with (
        patch.object(creds.models.User, "get_item", new=AsyncMock(return_value=None)),
        patch.object(
            creds.webauthn,
            "generate_authentication_options",
            return_value=options,
        ),
        patch.object(
            creds.webauthn.helpers,
            "options_to_json_dict",
            return_value={"challenge": "x"},
        ),
        patch.object(creds.redis, "set", new=AsyncMock()) as redis_set,
    ):
        result = await creds.generate_authentication_challenge(tenant)
    assert result == {"challenge": "x"}
    redis_set.assert_awaited_once()
