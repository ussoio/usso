"""
Captcha schemas and validation models.

This module defines Pydantic models for captcha challenges, validation requests,
and utility functions for captcha generation and verification.
"""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from enum import StrEnum
from functools import cached_property
from typing import Self

from captcha.image import ImageCaptcha
from pydantic import BaseModel, Field

from server.config import Settings
from server.db import redis
from server.exceptions import BadRequestError
from utils import texttools


def get_hashed_phrase(
    salt: str, secret_number: str, max_number: int, iat: int, exp: int, **kwargs: object
) -> str:
    """
    Generate a hashed phrase for captcha challenge.

    Args:
        salt: Random salt string.
        secret_number: The secret number to hash.
        max_number: Maximum number value.
        iat: Issued at timestamp.
        exp: Expiration timestamp.
        **kwargs: Additional unused keyword arguments.

    Returns:
        SHA256 hash of the phrase.

    """
    phrase = f"{salt}{secret_number}"
    return hashlib.sha256(phrase.encode()).hexdigest()


def get_signature(challenge: str, **kwargs: object) -> str:
    """
    Generate HMAC signature for a challenge string.

    Args:
        challenge: The challenge string to sign.
        **kwargs: Additional unused keyword arguments.

    Returns:
        HMAC-SHA256 signature hex digest.

    """
    return hmac.new(
        Settings.captcha_key.encode(), challenge.encode(), hashlib.sha256
    ).hexdigest()


# Salt prefix that marks a challenge as requiring the image code. The salt is
# part of the signed challenge, so a client cannot remove this marker.
# ``secrets.token_urlsafe`` never emits ".", so the prefix is unambiguous.
IMAGE_CODE_SALT_PREFIX = "img."


def code_key(signature: str) -> str:
    """Redis key of the image code bound to one challenge signature."""
    return f"captcha:code:{signature}"


class AltchaAlgorithm(StrEnum):
    """Supported hash algorithms for ALTCHA challenges."""

    SHA256 = "SHA-256"


class CodeChallenge(BaseModel):
    """
    Image captcha code challenge data.

    Attributes:
        image: Base64-encoded image data URL.
        length: Length of the secret code.
        audio: Optional audio captcha data URL.

    """

    image: str
    length: int
    audio: str | None = None


class ChallengeResponse(BaseModel):
    """Schema for captcha challenge response."""

    model_config = {"populate_by_name": True}

    challenge: str
    max_number: int = Field(
        default_factory=lambda: Settings.captcha_max_number,
        alias="maxnumber",
    )
    salt: str
    signature: str
    algorithm: AltchaAlgorithm = AltchaAlgorithm.SHA256
    exp: int = Field(
        default_factory=lambda: int(
            datetime.now(UTC).timestamp() + Settings.captcha_verification_duration
        )
    )
    iat: int = Field(default_factory=lambda: int(datetime.now(UTC).timestamp()))
    codeChallenge: CodeChallenge | None = None  # ruff:ignore[mixed-case-variable-in-class-scope]

    @classmethod
    async def get_random_challenge(
        cls, image_captcha: bool = False, fingerprint: str = ""
    ) -> Self:
        """
        Generate a random captcha challenge.

        Args:
            image_captcha: Whether to generate an image captcha.
            fingerprint: Client fingerprint for tracking.

        Returns:
            ChallengeResponse instance with generated challenge data.

        """
        iat = int(datetime.now(UTC).timestamp())
        exp = int(iat + Settings.captcha_verification_duration)
        prefix = IMAGE_CODE_SALT_PREFIX if image_captcha else ""
        salt = f"{prefix}{secrets.token_urlsafe(16)}_iat={iat}?expires={exp}"
        max_number = Settings.captcha_max_number
        if image_captcha:
            secret_length = 4 + secrets.randbelow(3)
            secret_code = texttools.generate_human_readable_code(secret_length)
            captcha_image = ImageCaptcha().generate(secret_code)
            # ImageCaptcha emits PNG; a jpeg data-URL breaks rendering in browsers.
            captcha_base64 = (
                "data:image/png;base64,"
                f"{base64.b64encode(captcha_image.getvalue()).decode()}"
            )
            secret_code = secret_code.casefold()
        else:
            secret_code = None
            captcha_base64 = None

        number = f"{secrets.randbelow(max_number + 1)}"
        challenge = get_hashed_phrase(salt, number, max_number, iat, exp)

        signature = hmac.new(
            Settings.captcha_key.encode(), challenge.encode(), hashlib.sha256
        ).hexdigest()

        if secret_code:
            # Bind the code to this challenge, not to the client fingerprint:
            # the fingerprint can differ between challenge and verify (proxy,
            # IP change) and is shared by concurrent challenges.
            key = code_key(signature)
            await redis.hset(
                key,
                mapping={
                    "code": secret_code,
                    "fingerprint": fingerprint,
                },
            )
            await redis.expire(key, Settings.captcha_verification_duration)

        payload = {
            "algorithm": AltchaAlgorithm.SHA256.value,
            "challenge": challenge,
            "max_number": max_number,
            "salt": salt,
            "signature": signature,
            "exp": exp,
            "iat": iat,
            "number": number,
            "codeChallenge": CodeChallenge(image=captcha_base64, length=secret_length)
            if secret_code
            else None,
        }
        res = cls(**payload)

        return res

    def get_hashed_phrase(self, secret_number: int) -> str:
        """
        Get hashed phrase for a given secret number.

        Args:
            secret_number: The secret number to hash.

        Returns:
            SHA256 hash of the phrase.

        """
        return get_hashed_phrase(
            self.salt, secret_number, self.max_number, self.iat, self.exp
        )

    def check_secret(self, secret_number: int) -> bool:
        """
        Check if the provided secret number matches the challenge.

        Args:
            secret_number: The secret number to verify.

        Returns:
            True if the secret number matches, False otherwise.

        """
        return self.challenge == get_hashed_phrase(
            self.salt, secret_number, self.max_number, self.iat, self.exp
        )

    def check_signature(self) -> bool:
        """
        Check if the signature is valid for the challenge.

        Returns:
            True if the signature is valid, False otherwise.

        """
        return self.signature == get_signature(self.challenge)


class ValidationRequest(BaseModel):
    """Schema for validating captcha payload."""

    altcha_payload: str

    @property
    def should_set_cookie(self) -> bool:
        """
        Check if the captcha should be set in a cookie.

        Returns:
            True if cookie should be set, False if payload matches system key.

        """
        return self.altcha_payload.rstrip("=") != Settings.captcha_key

    def get_cookie_payload(self, code: str | None = None) -> str:
        """
        Get the cookie payload from the altcha payload.

        Args:
            code: Optional code to include in the payload.

        Returns:
            Base64-encoded cookie payload string.

        """
        payload = self.decoded_payload
        if code is not None:
            payload["code"] = str(code).casefold()
        return base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    @property
    def decoded_payload(self) -> dict[str, object]:
        """
        Decode and parse the altcha payload.

        Returns:
            Dictionary containing decoded payload data.

        Raises:
            BadRequestError: If the payload cannot be decoded or parsed.

        """
        try:
            if self.altcha_payload == Settings.captcha_key.rstrip("="):
                return {}
            self.altcha_payload += "=" * (-len(self.altcha_payload) % 4)
            return json.loads(base64.b64decode(self.altcha_payload))
        except Exception as e:
            raise BadRequestError(
                error_code="captcha_error",
                detail="Invalid altcha payload",
                message={
                    "en": "Invalid altcha payload",
                    "fa": "کپچا تأیید نشد. دوباره تکمیل کنید.",
                },
            ) from e

    @cached_property
    def challenge(self) -> ChallengeResponse:
        """
        The challenge from the altcha payload.

        Returns:
            ChallengeResponse instance parsed from the decoded payload.

        """
        return ChallengeResponse(**self.decoded_payload)

    @cached_property
    def number(self) -> int:
        """
        The number from the altcha payload.

        Returns:
            The secret number from the payload, or -1 if not found.

        """
        return self.decoded_payload.get("number", -1)

    def _validate_timestamps(self) -> str | None:
        """
        Validate challenge timestamps.

        Checks that the challenge has valid issued-at and expiration timestamps
        and that it hasn't expired.

        Returns:
            Error message string if validation fails, None otherwise.

        """
        if self.challenge.salt.find("?expires=") > 0:
            exp = int(self.challenge.salt.split("?expires=")[1])
            self.challenge.exp = exp
        else:
            return "Invalid challenge"

        if self.challenge.salt.find("_iat=") > 0:
            iat = int(self.challenge.salt.split("_iat=")[1].split("?")[0])
            self.challenge.iat = iat
        else:
            return "Invalid challenge"

        if self.challenge.exp < datetime.now(UTC).timestamp():
            return "Expired challenge"

        if (
            datetime.now(UTC).timestamp() - self.challenge.iat
            > Settings.captcha_verification_duration
        ):
            return "Expired challenge"

    def _validate_challenge(self, number: int) -> str | None:
        """
        Validate challenge algorithm, secret, and signature.

        Args:
            number: The secret number to validate against the challenge.

        Returns:
            Error message string if validation fails, None otherwise.

        """
        if self.challenge.algorithm not in AltchaAlgorithm._value2member_map_:
            return "Invalid algorithm"

        if not self.challenge.check_secret(number):
            return "Invalid challenge"

        if not self.challenge.check_signature():
            return "Invalid signature"

    async def validate_usage(self) -> bool:
        """
        Check if the captcha has been used too many times.

        Tracks usage count in Redis and checks against the maximum allowed usage.

        Returns:
            True if usage is within limits, False if exceeded.

        """
        if self.altcha_payload.rstrip("=") == Settings.captcha_key.rstrip("="):
            return True

        key = f"captcha:usage:{self.challenge.signature}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, Settings.captcha_verification_duration)
        return count <= Settings.captcha_max_usage_count

    async def validate_code(self, code: str | None, fingerprint: str = "") -> bool:
        """
        Validate the captcha code against stored challenge.

        Challenges without the signed image marker need no code. Challenges
        with the marker fail closed: the stored code for this exact signature
        must exist and match. A wrong code deletes the stored code, so the
        client must request a new challenge. Letter case is ignored.

        Args:
            code: The captcha code to validate. If None, uses code from payload.
            fingerprint: Unused; kept for call-site compatibility.

        Returns:
            True if code is valid and matches, False otherwise.

        """
        del fingerprint
        if not self.challenge.salt.startswith(IMAGE_CODE_SALT_PREFIX):
            return True

        submitted = code if code is not None else self.decoded_payload.get("code")
        if submitted is None or not str(submitted).strip():
            return False

        key = code_key(self.challenge.signature)
        token: bytes | None = await redis.hget(key, "code")
        if token is None:
            return False

        if hmac.compare_digest(
            token.decode().casefold(), str(submitted).strip().casefold()
        ):
            return True

        await redis.delete(key)
        return False

    async def validate_error(
        self, code: str | None, fingerprint: str = "", *, count_usage: bool = True
    ) -> str | None:
        """
        Validate the captcha payload and return error message if invalid.

        Performs comprehensive validation including timestamps, usage count,
        code verification, and challenge validation.

        Args:
            code: Optional captcha code to validate.
            fingerprint: Client fingerprint for code validation.
            count_usage: Whether to increment and enforce usage limits.

        Returns:
            Error message string if validation fails, None if valid.

        """
        if self.altcha_payload.rstrip("=") == Settings.captcha_key.rstrip("="):
            return

        timestamp_error = self._validate_timestamps()
        if timestamp_error:
            return timestamp_error

        if count_usage and not await self.validate_usage():
            return "Captcha used too many times"

        if not await self.validate_code(code, fingerprint):
            return "Invalid code"

        return self._validate_challenge(self.number)
