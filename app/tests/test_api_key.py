"""test_api_key module."""

import logging

import httpx
import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def user_id(authenticated_client: httpx.AsyncClient) -> str:
    """Get the current user's ID from the auth endpoint."""
    resp = await authenticated_client.get("/auth/me")
    resp.raise_for_status()
    return resp.json().get("sub")


@pytest.mark.asyncio
async def test_api_key_lifecycle(
    authenticated_client: httpx.AsyncClient,
    captcha_client: httpx.AsyncClient,
    user_id: str,
) -> None:
    """Test the full lifecycle of an API key: create, verify, list, and delete."""
    resp = await authenticated_client.post(
        "/apikeys",
        json={"scopes": ["read:finance/*/*", "read:users/*/*?user_id="]},
    )
    resp.raise_for_status()

    generated_api_key = resp.json().get("api_key")
    resp_verify = await captcha_client.post(
        "/apikeys/verify",
        json={"api_key": generated_api_key},
    )
    logging.info(resp_verify.json())
    resp_verify.raise_for_status()

    resp_list = await authenticated_client.get("/apikeys")
    logging.info(resp_list.json())
    resp_list.raise_for_status()
    assert len(resp_list.json().get("items")) == 1

    uid = resp.json().get("uid")

    resp_delete = await authenticated_client.delete(f"/apikeys/{uid}")
    logging.info(resp_delete.json())
    resp_delete.raise_for_status()

    resp_verify_after_delete = await captcha_client.post(
        "/apikeys/verify",
        json={"api_key": generated_api_key},
    )
    assert resp_verify_after_delete.status_code == 401

    resp_list = await authenticated_client.get("/apikeys")
    logging.info(resp_list.json())
    resp_list.raise_for_status()
    assert len(resp_list.json().get("items")) == 0
