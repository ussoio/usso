"""Unit tests for case-insensitive image captcha code validation."""

import base64
import json
from unittest.mock import AsyncMock, patch

import pytest

from apps.captcha.schemas import ValidationRequest


def _validation_request(
    signature: str = "sig123", *, cookie_code: str | None = None
) -> ValidationRequest:
    payload = {
        "algorithm": "SHA-256",
        "challenge": "abc",
        "max_number": 10,
        "salt": "s_iat=1?expires=9999999999",
        "signature": signature,
        "number": 0,
        "iat": 1,
        "exp": 9999999999,
    }
    if cookie_code is not None:
        payload["code"] = cookie_code
    altcha_payload = base64.b64encode(json.dumps(payload).encode()).decode()
    return ValidationRequest(altcha_payload=altcha_payload)


@pytest.mark.asyncio
async def test_validate_code_accepts_mixed_case_input() -> None:
    """Image captcha code should match regardless of letter casing."""
    request = _validation_request()
    with patch(
        "apps.captcha.schemas.redis.hget",
        new=AsyncMock(side_effect=[b"AbCd", b"sig123"]),
    ):
        assert await request.validate_code("aBcD", fingerprint="fp1") is True


@pytest.mark.asyncio
async def test_validate_code_accepts_mixed_case_cookie_payload() -> None:
    """Code stored in cookie payload should also compare case-insensitively."""
    request = _validation_request(cookie_code="XyZ9")
    with patch(
        "apps.captcha.schemas.redis.hget",
        new=AsyncMock(side_effect=[b"xyz9", b"sig123"]),
    ):
        assert await request.validate_code(None, fingerprint="fp1") is True


@pytest.mark.asyncio
async def test_validate_code_ignores_stale_signature_for_fingerprint() -> None:
    """A leftover image code for another challenge must not fail this verify."""
    request = _validation_request(signature="sig-current")
    with patch(
        "apps.captcha.schemas.redis.hget",
        new=AsyncMock(side_effect=[b"AbCd", b"sig-other"]),
    ):
        assert await request.validate_code(None, fingerprint="fp1") is True


@pytest.mark.asyncio
async def test_validate_code_rejects_wrong_code_for_matching_signature() -> None:
    request = _validation_request(signature="sig123")
    with (
        patch(
            "apps.captcha.schemas.redis.hget",
            new=AsyncMock(side_effect=[b"AbCd", b"sig123"]),
        ),
        patch("apps.captcha.schemas.redis.delete", new=AsyncMock()) as delete,
    ):
        assert await request.validate_code("nope", fingerprint="fp1") is False
        delete.assert_awaited_once_with("captcha:code:fp1")
