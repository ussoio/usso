"""Direct-handler tests for captcha attempt tracking."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Response

from apps.captcha import routes
from server.exceptions import BadRequestError


def _request(*, altcha: str | None = None) -> SimpleNamespace:
    headers = {"host": "login.example.test"}
    if altcha:
        headers["x-altcha-payload"] = altcha
    return SimpleNamespace(headers=headers, cookies={})


def _challenge() -> SimpleNamespace:
    return SimpleNamespace(
        model_dump=MagicMock(
            return_value={
                "algorithm": "SHA-256",
                "challenge": "challenge",
                "signature": "signature",
                "ignored": "not-returned",
            }
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored_attempts", "threshold", "show_image"),
    [(None, 2, False), (b"1", 2, False), (b"2", 2, True)],
)
async def test_get_challenge_tracks_attempts_and_threshold(
    stored_attempts: bytes | None, threshold: int, show_image: bool
) -> None:
    request = _request()
    response = MagicMock(spec=Response)
    tenant = SimpleNamespace(config=SimpleNamespace(image_captcha_tries=threshold))
    expected_attempts = int(stored_attempts or 0) + 1
    redis = SimpleNamespace(
        incr=AsyncMock(return_value=expected_attempts), expire=AsyncMock()
    )
    challenge = _challenge()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "generate_fingerprint", return_value="fingerprint"),
        patch.object(routes, "redis", redis),
        patch.object(
            routes.ChallengeResponse,
            "get_random_challenge",
            new=AsyncMock(return_value=challenge),
        ) as get_random,
    ):
        result = await routes.get_challenge(request, response)

    redis.incr.assert_awaited_once_with("captcha:attempts:fingerprint")
    if expected_attempts == 1:
        redis.expire.assert_awaited_once_with("captcha:attempts:fingerprint", 3600)
    else:
        redis.expire.assert_not_awaited()
    get_random.assert_awaited_once_with(
        image_captcha=show_image, fingerprint="fingerprint"
    )
    response.delete_cookie.assert_called_once_with(
        "altcha_payload",
        domain=".example.test",
        samesite="lax",
        httponly=True,
        secure=True,
    )
    assert result == {
        "algorithm": "SHA-256",
        "challenge": "challenge",
        "signature": "signature",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
async def test_get_challenge_altcha_validation_paths(valid: bool) -> None:
    request = _request(altcha="signed-payload")
    response = MagicMock(spec=Response)
    tenant = SimpleNamespace(config=SimpleNamespace(image_captcha_tries=10))
    redis = SimpleNamespace(incr=AsyncMock(return_value=1), expire=AsyncMock())
    validation = AsyncMock()
    if not valid:
        validation.side_effect = BadRequestError(
            error_code="captcha_error", detail="bad", message={"en": "bad"}
        )
    get_random = AsyncMock(return_value=_challenge())
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "generate_fingerprint", return_value="fingerprint"),
        patch.object(routes, "_validate_altcha_payload", new=validation),
        patch.object(routes, "redis", redis),
        patch.object(routes.ChallengeResponse, "get_random_challenge", new=get_random),
    ):
        await routes.get_challenge(request, response)

    validation.assert_awaited_once_with(
        "signed-payload", fingerprint="fingerprint", count_usage=False
    )
    if valid:
        redis.incr.assert_not_awaited()
        redis.expire.assert_not_awaited()
        response.delete_cookie.assert_not_called()
        get_random.assert_awaited_once_with(
            image_captcha=False, fingerprint="fingerprint"
        )
    else:
        redis.incr.assert_awaited_once()
        response.delete_cookie.assert_called_once()


@pytest.mark.asyncio
async def test_verify_returns_static_success_payload() -> None:
    result = await routes.verify(SimpleNamespace(), payload="verified")
    assert result == {
        "verified": True,
        "payload": "verified",
        "message": "captcha verified successfully",
    }
