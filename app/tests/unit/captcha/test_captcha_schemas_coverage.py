"""Focused unit and branch coverage for captcha schemas."""

import base64
import io
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.captcha import schemas
from server.exceptions import BadRequestError


def _challenge_payload(
    *, number: int = 7, iat: int | None = None, exp: int | None = None
) -> dict:
    iat = iat if iat is not None else int(datetime.now(UTC).timestamp())
    exp = (
        exp if exp is not None else iat + schemas.Settings.captcha_verification_duration
    )
    salt = f"salt_iat={iat}?expires={exp}"
    challenge = schemas.get_hashed_phrase(
        salt, number, schemas.Settings.captcha_max_number, iat, exp
    )
    return {
        "algorithm": schemas.AltchaAlgorithm.SHA256.value,
        "challenge": challenge,
        "max_number": schemas.Settings.captcha_max_number,
        "salt": salt,
        "signature": schemas.get_signature(challenge),
        "exp": exp,
        "iat": iat,
        "number": number,
    }


def _image_challenge_payload(number: int = 7) -> dict:
    iat = int(datetime.now(UTC).timestamp())
    exp = iat + schemas.Settings.captcha_verification_duration
    salt = f"{schemas.IMAGE_CODE_SALT_PREFIX}salt_iat={iat}?expires={exp}"
    challenge = schemas.get_hashed_phrase(
        salt, number, schemas.Settings.captcha_max_number, iat, exp
    )
    return {
        **_challenge_payload(number=number, iat=iat, exp=exp),
        "challenge": challenge,
        "salt": salt,
        "signature": schemas.get_signature(challenge),
    }


def _request(payload: dict | None = None) -> schemas.ValidationRequest:
    raw = json.dumps(payload or _challenge_payload()).encode()
    encoded = base64.b64encode(raw).decode().rstrip("=")
    return schemas.ValidationRequest(altcha_payload=encoded)


def test_hash_signature_and_challenge_checks() -> None:
    payload = _challenge_payload(number=3)
    challenge = schemas.ChallengeResponse(**payload)
    assert challenge.get_hashed_phrase(3) == payload["challenge"]
    assert challenge.check_secret(3) is True
    assert challenge.check_secret(4) is False
    assert challenge.check_signature() is True
    challenge.signature = "bad"
    assert challenge.check_signature() is False


@pytest.mark.asyncio
async def test_random_challenge_without_image_is_signed() -> None:
    redis = SimpleNamespace(hset=AsyncMock(), expire=AsyncMock())
    with (
        patch.object(schemas, "redis", redis),
        patch.object(schemas.secrets, "token_urlsafe", return_value="salt"),
        patch.object(schemas.secrets, "randbelow", return_value=7),
    ):
        challenge = await schemas.ChallengeResponse.get_random_challenge()
    assert challenge.codeChallenge is None
    assert challenge.check_secret(7) is True
    assert challenge.check_signature() is True
    redis.hset.assert_not_awaited()


@pytest.mark.asyncio
async def test_random_image_challenge_stores_casefolded_code() -> None:
    redis = SimpleNamespace(hset=AsyncMock(), expire=AsyncMock())
    image = MagicMock()
    image.generate.return_value = io.BytesIO(b"jpeg-data")
    with (
        patch.object(schemas, "redis", redis),
        patch.object(schemas, "ImageCaptcha", return_value=image),
        patch.object(
            schemas.texttools, "generate_human_readable_code", return_value="AbC9"
        ),
        patch.object(schemas.secrets, "token_urlsafe", return_value="salt"),
        patch.object(schemas.secrets, "randbelow", side_effect=[0, 5]),
    ):
        challenge = await schemas.ChallengeResponse.get_random_challenge(
            image_captcha=True, fingerprint="fp"
        )
    assert challenge.codeChallenge.length == 4
    assert challenge.codeChallenge.image.startswith("data:image/png;base64,")
    assert challenge.salt.startswith(schemas.IMAGE_CODE_SALT_PREFIX)
    assert challenge.check_signature() is True
    assert redis.hset.await_args.kwargs["mapping"]["code"] == "abc9"
    redis.expire.assert_awaited_once_with(
        schemas.code_key(challenge.signature),
        schemas.Settings.captcha_verification_duration,
    )


def test_validation_request_decoding_cookie_and_number() -> None:
    request = _request()
    assert request.should_set_cookie is True
    assert request.number == 7
    assert request.challenge.check_secret(7) is True

    cookie = request.get_cookie_payload("MiXeD")
    decoded = json.loads(base64.b64decode(cookie + "=" * (-len(cookie) % 4)))
    assert decoded["code"] == "mixed"

    bypass = schemas.ValidationRequest(
        altcha_payload=schemas.Settings.captcha_key.rstrip("=")
    )
    assert bypass.should_set_cookie is False
    assert bypass.decoded_payload == {}


def test_invalid_payload_raises_bad_request() -> None:
    request = schemas.ValidationRequest(altcha_payload="not-json")
    with pytest.raises(BadRequestError) as exc:
        _ = request.decoded_payload
    assert exc.value.error_code == "captcha_error"


def test_timestamp_validation_missing_and_expired_branches() -> None:
    request = _request()
    request.__dict__["challenge"] = SimpleNamespace(salt="no-expiry", exp=0, iat=0)
    assert request._validate_timestamps() == "Invalid challenge"

    request = _request()
    request.__dict__["challenge"] = SimpleNamespace(
        salt="salt?expires=9999999999", exp=0, iat=0
    )
    assert request._validate_timestamps() == "Invalid challenge"

    now = int(datetime.now(UTC).timestamp())
    assert (
        _request(_challenge_payload(iat=now - 20, exp=now - 1))._validate_timestamps()
        == "Expired challenge"
    )
    old_iat = now - schemas.Settings.captcha_verification_duration - 1
    assert (
        _request(_challenge_payload(iat=old_iat, exp=now + 60))._validate_timestamps()
        == "Expired challenge"
    )
    assert (
        _request(_challenge_payload(iat=now, exp=now + 60))._validate_timestamps()
        is None
    )


def test_challenge_validation_error_and_success_branches() -> None:
    request = _request()
    request.__dict__["challenge"] = SimpleNamespace(algorithm="MD5")
    assert request._validate_challenge(7) == "Invalid algorithm"

    challenge = SimpleNamespace(
        algorithm=schemas.AltchaAlgorithm.SHA256,
        check_secret=MagicMock(return_value=False),
        check_signature=MagicMock(return_value=True),
    )
    request.__dict__["challenge"] = challenge
    assert request._validate_challenge(7) == "Invalid challenge"
    challenge.check_secret.return_value = True
    challenge.check_signature.return_value = False
    assert request._validate_challenge(7) == "Invalid signature"
    challenge.check_signature.return_value = True
    assert request._validate_challenge(7) is None


@pytest.mark.asyncio
async def test_validate_usage_bypass_allowed_and_exceeded() -> None:
    bypass = schemas.ValidationRequest(
        altcha_payload=schemas.Settings.captcha_key.rstrip("=")
    )
    assert await bypass.validate_usage() is True

    redis = SimpleNamespace(incr=AsyncMock(return_value=1), expire=AsyncMock())
    request = _request()
    with patch.object(schemas, "redis", redis):
        assert await request.validate_usage() is True
    redis.expire.assert_awaited_once()

    redis.incr.return_value = schemas.Settings.captcha_max_usage_count + 1
    with patch.object(schemas, "redis", redis):
        assert await request.validate_usage() is False


@pytest.mark.asyncio
async def test_validate_code_missing_match_and_mismatch() -> None:
    # Plain PoW challenge (no signed image marker) needs no code.
    plain = _request()
    redis = SimpleNamespace(hget=AsyncMock(), delete=AsyncMock())
    with patch.object(schemas, "redis", redis):
        assert await plain.validate_code(None, "fp") is True
    redis.hget.assert_not_awaited()

    request = _request({**_image_challenge_payload(), "code": "AbC9"})
    key = schemas.code_key(request.challenge.signature)

    redis.hget = AsyncMock(return_value=b"abc9")
    with patch.object(schemas, "redis", redis):
        assert await request.validate_code("ABC9", "fp") is True
        assert await request.validate_code(None, "fp") is True
    redis.hget.assert_awaited_with(key, "code")

    # Image challenge whose stored code is gone (expired/consumed) fails closed.
    redis.hget = AsyncMock(return_value=None)
    with patch.object(schemas, "redis", redis):
        assert await request.validate_code("ABC9", "fp") is False

    # Wrong code fails and clears the stored code.
    redis.hget = AsyncMock(return_value=b"wrong")
    with patch.object(schemas, "redis", redis):
        assert await request.validate_code("ABC9", "fp") is False
    redis.delete.assert_awaited_once_with(key)


@pytest.mark.asyncio
async def test_image_challenge_without_code_is_rejected() -> None:
    """Regression: an image challenge must not verify with no/empty code."""
    request = _request(_image_challenge_payload())
    redis = SimpleNamespace(hget=AsyncMock(return_value=b"abc9"), delete=AsyncMock())
    with patch.object(schemas, "redis", redis):
        assert await request.validate_code(None, "fp") is False
        assert await request.validate_code("   ", "fp") is False


@pytest.mark.asyncio
async def test_image_code_does_not_depend_on_fingerprint() -> None:
    """Regression: a different verify fingerprint must not skip the code check."""
    request = _request(_image_challenge_payload())
    redis = SimpleNamespace(hget=AsyncMock(return_value=b"abc9"), delete=AsyncMock())
    with patch.object(schemas, "redis", redis):
        assert await request.validate_code("zzzz", "other-fp") is False
    redis.delete.assert_awaited_once()


def test_image_marker_cannot_be_stripped_without_breaking_signature() -> None:
    payload = _image_challenge_payload()
    payload["salt"] = payload["salt"].removeprefix(schemas.IMAGE_CODE_SALT_PREFIX)
    challenge = schemas.ChallengeResponse(**payload)
    # The marker is hashed into ``challenge``; removing it breaks the PoW check.
    assert challenge.check_secret(payload["number"]) is False


@pytest.mark.asyncio
async def test_validate_error_short_circuits_each_failure() -> None:
    bypass = schemas.ValidationRequest(
        altcha_payload=schemas.Settings.captcha_key.rstrip("=")
    )
    assert await bypass.validate_error(None) is None

    request = _request()
    with patch.object(
        schemas.ValidationRequest, "_validate_timestamps", return_value="expired"
    ):
        assert await request.validate_error(None) == "expired"

    with (
        patch.object(
            schemas.ValidationRequest, "_validate_timestamps", return_value=None
        ),
        patch.object(
            schemas.ValidationRequest,
            "validate_usage",
            new=AsyncMock(return_value=False),
        ),
    ):
        assert await request.validate_error(None) == "Captcha used too many times"

    with (
        patch.object(
            schemas.ValidationRequest, "_validate_timestamps", return_value=None
        ),
        patch.object(
            schemas.ValidationRequest,
            "validate_usage",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            schemas.ValidationRequest,
            "validate_code",
            new=AsyncMock(return_value=False),
        ),
    ):
        assert await request.validate_error(None) == "Invalid code"

    with (
        patch.object(
            schemas.ValidationRequest, "_validate_timestamps", return_value=None
        ),
        patch.object(
            schemas.ValidationRequest,
            "validate_usage",
            new=AsyncMock(return_value=False),
        ) as usage,
        patch.object(
            schemas.ValidationRequest, "validate_code", new=AsyncMock(return_value=True)
        ),
        patch.object(
            schemas.ValidationRequest, "_validate_challenge", return_value=None
        ) as validate,
    ):
        assert await request.validate_error(None, count_usage=False) is None
    usage.assert_not_awaited()
    validate.assert_called_once_with(7)
