"""conftest module."""

from collections.abc import AsyncGenerator

try:
    import httpx2 as httpx
except ImportError:
    import httpx

import pytest_asyncio

from apps.identity.auth.enums import AuthSecret
from apps.identity.user.models import Credential, User, UserIdentifier
from apps.tenant.models import Tenant
from utils.hasher import PasswordHasherService


@pytest_asyncio.fixture(scope="session")
async def sample_user(
    initial_tenant: Tenant, captcha_client: httpx.AsyncClient
) -> AsyncGenerator[User]:
    user = await User(
        tenant_id=initial_tenant.uid,
        is_active=True,
        is_limited=False,
        activation_status="active",
    ).save()
    await UserIdentifier(
        type="email",
        identifier="user@localhost",
        user_id=user.uid,
        tenant_id=user.tenant_id,
    ).save()
    await UserIdentifier(
        type="phone",
        identifier="989352212847",
        user_id=user.uid,
        tenant_id=user.tenant_id,
    ).save()
    # OTP credentials are stored hashed (same as production messaging path).
    await Credential(
        method=AuthSecret.PHONE_OTP,
        secret=PasswordHasherService().hash_password("123456"),
        user_id=user.uid,
        tenant_id=user.tenant_id,
    ).save()

    login_data = {
        "type": "phone",
        "identifier": "989352212847",
        "method": "phone/otp",
        "secret": "123456",
    }
    resp = await captcha_client.post("/auth/login", json=login_data)
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"

    otp_cred = await Credential.find_one({
        "user_id": user.uid,
        "tenant_id": user.tenant_id,
        "method": AuthSecret.PHONE_OTP,
        "is_deleted": False,
    })
    if otp_cred is not None:
        await Credential.delete_item(otp_cred)

    yield user
    await user.delete()
