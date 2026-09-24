"""test_service module."""

import pyotp
import pytest
from beanie.exceptions import RevisionIdWasChanged
from pymongo.errors import DuplicateKeyError

from apps.identity.auth import enums as auth_enums
from apps.identity.user.models import UserIdentifier
from apps.identity.user.services import (
    PasswordHasherService,
    validate_totp,
)

# Keep argon2 params snappy for multitenant login; allow headroom for CI load.
pytestmark = pytest.mark.timeout(0.5, func_only=True)


def test_password_hash() -> None:
    """Test password hashing and verification."""
    password = "secret_password_123"

    # Initialize with balanced default for multitenant
    hasher_service = PasswordHasherService(
        memory_cost=12288, time_cost=3, parallelism=1
    )

    # Hash the password
    hashed_password = hasher_service.hash_password(password)

    # Verify the password
    assert hasher_service.verify_password(hashed_password, password)


def test_unsalted_legacy_digest_is_rejected() -> None:
    """Fast legacy digests must never authenticate a password."""
    legacy_digest = "5ebe2294ecd0e0f08eab7690d2a6ee69"
    assert not PasswordHasherService().verify_password(legacy_digest, "secret")


@pytest.mark.asyncio
async def test_unique_identifier_per_tenant() -> None:
    """Test that identifiers are unique per tenant."""
    identifier1 = UserIdentifier(
        tenant_id="tenant1",
        type=auth_enums.AuthIdentifier.EMAIL,
        identifier="test@example.com",
        user_id="test_unique_user1",
    )
    await identifier1.save()

    identifier2 = UserIdentifier(
        tenant_id="tenant1",
        type=auth_enums.AuthIdentifier.EMAIL,
        identifier="test@example.com",
        user_id="test_unique_user2",
    )
    with pytest.raises((DuplicateKeyError, RevisionIdWasChanged)):
        await identifier2.save()

    identifier3 = UserIdentifier(
        tenant_id="tenant2",
        type=auth_enums.AuthIdentifier.EMAIL,
        identifier="test@example.com",
        user_id="test_unique_user2",
    )
    await identifier3.save()


def test_validate_totp_valid_code() -> None:
    """Test that validate_totp returns True for a valid TOTP code."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert validate_totp(secret=secret, code=code) is True


def test_validate_totp_invalid_code() -> None:
    """Test that validate_totp returns False for an invalid TOTP code."""
    secret = pyotp.random_base32()
    invalid_code = "123456"  # unlikely to be valid
    assert validate_totp(secret=secret, code=invalid_code) is False


def test_validate_totp_expired_code() -> None:
    """Test that validate_totp returns False for an expired TOTP code."""
    import time

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    # 31 seconds ago code
    code = totp.at(for_time=time.time() - 31)
    assert validate_totp(secret=secret, code=code) is False
