"""test_auth module."""

import logging
import os

import httpx
import pytest

from server.server import app as fastapi_app
from tests.conftest import TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.mark.asyncio
async def test_login_endpoint_exists(
    captcha_client: httpx.AsyncClient,
) -> None:
    """Test that login endpoint exists and returns 200 for GET /auth/."""
    response = await captcha_client.get("/auth/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_login_without_data(captcha_client: httpx.AsyncClient) -> None:
    """Test login endpoint without data returns 422."""
    response = await captcha_client.post("/auth/login", json={})
    logging.info(f"{response.json()=}")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_new_user(captcha_client: httpx.AsyncClient) -> None:
    """Test login with invalid data."""
    response = await captcha_client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": "test@uln.me",
            "method": "password",
            "secret": "password123",
        },
    )
    logging.info(response.json())
    assert response.status_code == 200
    assert response.json()["status"] == "verification_required"


@pytest.mark.asyncio
async def test_login_user(captcha_client: httpx.AsyncClient) -> None:
    """Test login with valid data."""
    response = await captcha_client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": os.getenv("SUPERADMIN_EMAIL"),
            "method": "password",
            "secret": os.getenv("SUPERADMIN_PASSWORD"),
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"

    refresh_token = response.json()["tokens"]["refresh"]

    refresh = await captcha_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh.status_code == 200
    assert refresh.json()["status"] == "refreshed"
    assert refresh.json()["tokens"]["access"] is not None
    assert refresh.json()["tokens"]["refresh"] is not None


@pytest.mark.asyncio
async def test_login_user_cookie(captcha_client: httpx.AsyncClient) -> None:
    """Test login with valid data using cookies."""
    browser_headers = {"User-Agent": "Mozilla/5.0 (compatible; test)"}
    response = await captcha_client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": os.getenv("SUPERADMIN_EMAIL"),
            "method": "password",
            "secret": os.getenv("SUPERADMIN_PASSWORD"),
        },
        headers=browser_headers,
    )
    logging.info(response.json())
    assert response.status_code == 200
    assert response.json()["status"] == "completed"

    logging.info(captcha_client.cookies.keys())
    refresh = await captcha_client.post("/auth/refresh", headers=browser_headers)
    logging.info(refresh.json())
    assert refresh.status_code == 200
    assert refresh.json()["status"] == "refreshed"
    assert "tokens" not in refresh.json()


@pytest.mark.asyncio
async def test_login_user_cookie_get_refresh(captcha_client: httpx.AsyncClient) -> None:
    """Browser clients may still call GET /auth/refresh with cookies."""
    browser_headers = {"User-Agent": "Mozilla/5.0 (compatible; test)"}
    response = await captcha_client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": os.getenv("SUPERADMIN_EMAIL"),
            "method": "password",
            "secret": os.getenv("SUPERADMIN_PASSWORD"),
        },
        headers=browser_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"

    refresh = await captcha_client.get("/auth/refresh", headers=browser_headers)
    assert refresh.status_code == 200
    assert refresh.json()["status"] == "refreshed"
    assert "tokens" not in refresh.json()


@pytest.mark.asyncio
async def test_invalid_data(captcha_client: httpx.AsyncClient) -> None:
    """Test login with wrong password returns unauthorized."""
    response = await captcha_client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": os.getenv("SUPERADMIN_EMAIL"),
            "method": "password",
            "secret": "definitely-wrong-password",
        },
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout(captcha_client: httpx.AsyncClient) -> None:
    """Logout should invalidate the caller's refresh session."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url=captcha_client.base_url,
        headers=dict(captcha_client.headers),
    ) as client:
        login = await client.post(
            "/auth/login",
            json={
                "type": "email",
                "identifier": TEST_ADMIN_EMAIL,
                "method": "password",
                "secret": TEST_ADMIN_PASSWORD,
            },
        )
        login.raise_for_status()
        access_token = login.json()["tokens"]["access"]
        client.headers["authorization"] = f"bearer {access_token}"
        response = await client.post("/auth/logout")
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_logout_cookie(captcha_client: httpx.AsyncClient) -> None:
    """Test login with invalid data."""
    response = await captcha_client.post("/auth/logout")
    assert response.status_code == 204
