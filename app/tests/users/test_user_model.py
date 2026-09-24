"""test_user_model module."""

import logging
import secrets

import pyotp
import pytest
import pytest_asyncio

from apps.access_control.role.models import Role
from apps.identity.auth import enums as auth_enums
from apps.identity.auth import schemas as auth_schemas
from apps.identity.auth.enums import AuthSecret
from apps.identity.auth.schemas import LoginRequest, Secret
from apps.identity.user.models import User, UserIdentifier
from apps.identity.user.schemas import CredentialSchema
from apps.identity.user.services import (
    PasswordHasherService,
    add_credential,
    authenticate_user,
    create_user,
    find_user,
)
from apps.tenant.models import Tenant


@pytest.fixture(scope="module")
def password() -> str:
    return secrets.token_hex(16)


@pytest.fixture(scope="module")
def otp_secret() -> str:
    return pyotp.random_base32()


@pytest_asyncio.fixture(scope="module")
async def tenant() -> Tenant:
    tenant = Tenant(
        name="Default Tenant",
        domains=["user-model.localhost"],
        uid="tenant1",
        user_id="user_test1",
    )
    await tenant.save()
    return tenant


@pytest_asyncio.fixture(scope="module")
async def user(tenant: Tenant, password: str, otp_secret: str) -> User:
    user = await create_user(
        login=LoginRequest(
            type=auth_enums.AuthIdentifier.EMAIL,
            identifier="test@test.uln.me",
            method=AuthSecret.PASSWORD,
            secret=password,
        ),
        tenant=tenant,
    )
    await add_credential(
        user=user,
        secret=Secret(
            method=AuthSecret.TOTP,
            secret=otp_secret,
        ),
    )
    return user
    user = User(
        name="Test",
        is_active=True,
        tenant_id="local",
        uid="user_test1",
    )
    user_identifier = UserIdentifier(
        type=auth_enums.AuthIdentifier.EMAIL,
        identifier="admin@localhost",
        user_id=user.uid,
        tenant_id=user.tenant_id,
    )
    roles = [
        Role(
            name="admin",
            description="Admin role",
            tenant_id="local",
        ),
        Role(
            name="user",
            description="User role",
            tenant_id="local",
        ),
    ]
    user.tenant = tenant
    user.roles = [role.name for role in roles]
    user_identifier.user_id = user.uid
    user_identifier.tenant_id = tenant.uid
    for role in roles:
        role.tenant_id = tenant.uid
        await role.save()

    user.credentials = [
        CredentialSchema(
            method=AuthSecret.PASSWORD,
            secret=PasswordHasherService().hash_password(password),
            enabled=True,
            user_id=user.uid,
            tenant_id=tenant.uid,
        ),
        CredentialSchema(
            method=AuthSecret.TOTP,
            secret=otp_secret,
            enabled=True,
            user_id=user.uid,
            tenant_id=tenant.uid,
        ),
    ]

    user.current_identifier = user_identifier
    await user_identifier.save()
    await user.save()
    return user


@pytest.mark.asyncio
async def test_find_user(tenant: Tenant, user: User) -> None:
    identifier = auth_schemas.Identifier(
        type=auth_enums.AuthIdentifier.EMAIL,
        identifier="test@test.uln.me",
    )
    user = await find_user(
        identifier=identifier,
        tenant_id="tenant1",
    )

    logging.info(f"{user=}")


@pytest.mark.asyncio
async def test_authenticate_user_with_pass(
    tenant: Tenant, user: User, password: str
) -> None:
    """Test authenticate_user returns user for valid TOTP and None for invalid code."""
    # Valid TOTP
    login_req = Secret(method=AuthSecret.PASSWORD, secret=password)
    assert await authenticate_user(user=user, secret=login_req)

    # Invalid TOTP
    login_req_invalid = Secret(method=AuthSecret.PASSWORD, secret=password + "1")
    assert not await authenticate_user(user=user, secret=login_req_invalid)


@pytest.mark.asyncio
async def test_authenticate_user_with_totp(
    tenant: Tenant, user: User, otp_secret: str
) -> None:
    """Test authenticate_user returns user for valid TOTP and None for invalid code."""
    totp = pyotp.TOTP(otp_secret)
    valid_code = totp.now()
    invalid_code = "123456"

    # Valid TOTP
    login_secret = Secret(method=AuthSecret.TOTP, secret=valid_code)
    assert await authenticate_user(user=user, secret=login_secret)

    # Invalid TOTP
    login_secret_invalid = Secret(method=AuthSecret.TOTP, secret=invalid_code)
    assert not await authenticate_user(user=user, secret=login_secret_invalid)
