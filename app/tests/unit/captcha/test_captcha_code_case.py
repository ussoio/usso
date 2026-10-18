"""Unit tests for case-insensitive image captcha code validation."""

import base64
import json
from unittest.mock import AsyncMock, patch

import pytest

from apps.captcha.schemas import IMAGE_CODE_SALT_PREFIX, ValidationRequest, code_key


def _validation_request(
    signature: str = "sig123",
    *,
    cookie_code: str | None = None,
    image: bool = True,
) -> ValidationRequest:
    prefix = IMAGE_CODE_SALT_PREFIX if image else ""
    payload = {
        "algorithm": "SHA-256",
        "challenge": "abc",
        "max_number": 10,
        "salt": f"{prefix}s_iat=1?expires=9999999999",
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
        new=AsyncMock(return_value=b"AbCd"),
    ) as hget:
        assert await request.validate_code("aBcD", fingerprint="fp1") is True
    hget.assert_awaited_once_with(code_key("sig123"), "code")


@pytest.mark.asyncio
async def test_validate_code_accepts_mixed_case_cookie_payload() -> None:
    """Code stored in cookie payload should also compare case-insensitively."""
    request = _validation_request(cookie_code="XyZ9")
    with patch(
        "apps.captcha.schemas.redis.hget",
        new=AsyncMock(return_value=b"xyz9"),
    ):
        assert await request.validate_code(None, fingerprint="fp1") is True


@pytest.mark.asyncio
async def test_validate_code_skips_plain_pow_challenge() -> None:
    """A challenge without the image marker needs no code."""
    request = _validation_request(image=False)
    with patch("apps.captcha.schemas.redis.hget", new=AsyncMock()) as hget:
        assert await request.validate_code(None, fingerprint="fp1") is True
    hget.assert_not_awaited()


@pytest.mark.asyncio
async def test_validate_code_rejects_wrong_code_for_matching_signature() -> None:
    request = _validation_request(signature="sig123")
    with (
        patch(
            "apps.captcha.schemas.redis.hget",
            new=AsyncMock(return_value=b"AbCd"),
        ),
        patch("apps.captcha.schemas.redis.delete", new=AsyncMock()) as delete,
    ):
        assert await request.validate_code("nope", fingerprint="fp1") is False
        delete.assert_awaited_once_with(code_key("sig123"))
