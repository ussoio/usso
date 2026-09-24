"""test_credentials module."""

import httpx
import pytest

from apps.identity.auth.enums import AuthSecret
from apps.identity.user.models import Credential, User, UserIdentifier


async def list_credentials(
    user_id: str, client: httpx.AsyncClient
) -> list[UserIdentifier]:
    response = await client.get(f"/users/{user_id}/credentials")
    return response.json()["items"]


@pytest.mark.asyncio
async def test_list_user_credentials_baseline(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    """The login OTP is consumed and no longer appears as an active credential."""
    uid = sample_user.uid
    credentials = await list_credentials(uid, authenticated_client)
    assert credentials == []


@pytest.mark.asyncio
async def test_generic_credential_creation(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    response = await authenticated_client.post(
        f"/users/{uid}/credentials",
        json={"method": "password", "secret": "test_crdential"},
    )
    assert response.status_code == 201
    credentials = await sample_user.get_credentials(not_cached=True)
    assert len(credentials) == 1
    assert credentials[0].method == AuthSecret.PASSWORD


@pytest.mark.asyncio
async def test_retrieve_user_credentials(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    await Credential(
        method=AuthSecret.PHONE_OTP,
        secret="fresh-otp",
        user_id=sample_user.uid,
        tenant_id=sample_user.tenant_id,
    ).save()
    credentials = await sample_user.get_credentials(not_cached=True)
    response = await authenticated_client.get(
        f"/users/{uid}/credentials/{credentials[0].uid}"
    )
    assert response.status_code == 405


@pytest.mark.asyncio
async def test_reset_user_credentials(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    await Credential(
        method=AuthSecret.PHONE_OTP,
        secret="reset-otp",
        user_id=sample_user.uid,
        tenant_id=sample_user.tenant_id,
    ).save()
    credentials = await sample_user.get_credentials(not_cached=True)
    phone_cred = next(
        (cred for cred in credentials if cred.method == AuthSecret.PHONE_OTP),
        None,
    )
    assert phone_cred is not None
    response = await authenticated_client.post(
        f"/users/{uid}/credentials/{phone_cred.uid}/reset"
    )
    assert response.status_code == 200
    reset_credential = await Credential.find_one({
        "uid": phone_cred.uid,
        "tenant_id": sample_user.tenant_id,
        "user_id": sample_user.uid,
    })
    assert reset_credential is not None
    assert reset_credential.is_deleted is True


@pytest.mark.asyncio
async def test_delete_user_credentials(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    await Credential(
        method=AuthSecret.PHONE_OTP,
        secret="delete-otp",
        user_id=sample_user.uid,
        tenant_id=sample_user.tenant_id,
    ).save()
    credentials = await sample_user.get_credentials(not_cached=True)
    active_credentials = [cred for cred in credentials if not cred.is_deleted]
    response = await authenticated_client.delete(
        f"/users/{uid}/credentials/{active_credentials[0].uid}"
    )
    assert response.status_code == 200
    remaining = await sample_user.get_credentials(not_cached=True)
    assert len([cred for cred in remaining if not cred.is_deleted]) == (
        len(active_credentials) - 1
    )
