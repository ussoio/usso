"""test_identifiers module."""

import logging

import httpx
import pytest

from apps.identity.user.models import User, UserIdentifier


async def list_identifiers(
    user_id: str, client: httpx.AsyncClient
) -> list[UserIdentifier]:
    response = await client.get(f"/users/{user_id}/identifiers")
    return response.json()["items"]


@pytest.mark.asyncio
async def test_list_user_identifiers(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    identifiers = await list_identifiers(uid, authenticated_client)
    assert len(identifiers) == 2


@pytest.mark.asyncio
async def test_create_user_identifier(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    response = await authenticated_client.post(
        f"/users/{uid}/identifiers",
        json={
            "type": "email",
            "identifier": "test_create_user_identifier@gmail.com",
        },
    )
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 201
    identifiers = await sample_user.get_identifiers(not_cached=True)
    assert len(identifiers) == 3
    assert identifiers[2].type == "email"
    assert identifiers[2].identifier == "test_create_user_identifier@gmail.com"


@pytest.mark.asyncio
async def test_retrieve_user_identifiers(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    identifiers = await sample_user.get_identifiers()
    response = await authenticated_client.get(
        f"/users/{uid}/identifiers/{identifiers[0].uid}"
    )
    assert response.status_code == 405


@pytest.mark.asyncio
async def test_update_user_identifier(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    identifiers = await sample_user.get_identifiers()
    response = await authenticated_client.patch(
        f"/users/{uid}/identifiers/{identifiers[0].uid}",
        json={
            "is_active": False,
        },
    )
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 200
    assert not resp_json["is_active"]

    identifiers = await list_identifiers(uid, authenticated_client)
    assert not identifiers[0]["is_active"]
    assert identifiers[1]["is_active"]
    assert identifiers[2]["is_active"]


@pytest.mark.asyncio
async def test_delete_user_identifier(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid

    identifiers = await list_identifiers(uid, authenticated_client)
    id_0_id = identifiers[0]["uid"]
    response = await authenticated_client.delete(f"/users/{uid}/identifiers/{id_0_id}")
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 200

    identifiers = await list_identifiers(uid, authenticated_client)
    assert len(identifiers) == 2


@pytest.mark.asyncio
async def test_resend_user_identifier(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    identifiers = await list_identifiers(uid, authenticated_client)
    assert len(identifiers) == 2
    phone = next(item for item in identifiers if item["type"] == "phone")
    response = await authenticated_client.post(
        f"/users/{uid}/identifiers/{phone['uid']}/resend"
    )
    resp_json = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 200
    if resp_json is not None:
        assert "otp" in resp_json
