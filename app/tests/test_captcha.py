"""test_captcha module."""

import base64
import json
from collections.abc import AsyncGenerator

import httpx
import pytest
import pytest_asyncio
from httpx import AsyncClient

from apps.captcha.schemas import ChallengeResponse
from server.server import app as fastapi_app
from tests.conftest import _api_base_url


@pytest_asyncio.fixture(scope="function")
async def client() -> AsyncGenerator[httpx.AsyncClient]:
    """Fixture to provide an AsyncClient for FastAPI app."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url=f"{_api_base_url()}/",
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Existing tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_challenge(client: AsyncClient) -> None:
    resp = await client.get("/captcha/challenge")
    assert resp.status_code == 200
    data = resp.json()
    assert "challenge" in data
    assert "signature" in data
    assert "salt" in data


@pytest.mark.asyncio
async def test_validate_missing_payload(client: AsyncClient) -> None:
    resp = await client.post("/captcha/verify", json={})
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "captcha_error"


@pytest.mark.asyncio
async def test_validate_success(client: AsyncClient) -> None:
    resp = await client.get("/captcha/challenge")
    challenge = ChallengeResponse(**resp.json())
    for num in range(challenge.max_number):
        if challenge.check_secret(num):
            break
    altcha_payload = base64.b64encode(
        json.dumps(challenge.model_dump() | {"number": num}).encode()
    ).decode()
    resp2 = await client.post("/captcha/verify", json={"payload": altcha_payload})
    assert resp2.status_code == 200
    assert resp2.json()["message"] == "captcha verified successfully"


@pytest.mark.asyncio
async def test_validate_invalid_signature(client: AsyncClient) -> None:
    resp = await client.get("/captcha/challenge")
    challenge = resp.json()
    # خراب کردن signature
    challenge["signature"] = "invalid"
    challenge["altcha_payload"] = base64.b64encode(
        json.dumps(challenge).encode()
    ).decode()
    resp2 = await client.post(
        "/captcha/verify",
        json={"payload": challenge["altcha_payload"]},
    )
    assert resp2.status_code == 400
    assert resp2.json()["error_code"] == "captcha_error"


@pytest.mark.asyncio
async def test_validate_invalid_base64(client: AsyncClient) -> None:
    resp = await client.post("/captcha/verify", json={"payload": "!!!notbase64!!!"})
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "captcha_error"


# ---------------------------------------------------------------------------
# Task 1.2 — Captcha challenge response format tests
# Moved to tests/captcha/test_challenge_response_format.py
# (pure unit tests that don't require DB or rate limiter initialization)
# ---------------------------------------------------------------------------
