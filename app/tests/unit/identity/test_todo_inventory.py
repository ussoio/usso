"""Unit tests for referral invite extraction, birth date, ACR, and API key gates."""

from datetime import date
from unittest.mock import MagicMock, patch

import pytest

from apps.identity.api_key import services as api_key_services
from apps.identity.auth.services.token import (
    ACR_BASIC,
    ACR_MFA,
    resolve_acr,
    resolve_signing_level,
)
from apps.identity.referral.services import extract_referral_code
from server.exceptions import BadRequestError, ForbiddenError, TooManyRequestsError
from utils.validators import normalize_birth_date


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("  ABC12  ", "ABC12"),
        ("https://app.example/join?referral_code=INVITE1", "INVITE1"),
        ("https://app.example/x?ref=R2", "R2"),
        ("/invite/CODE99", "CODE99"),
        ("https://x/r/PATHCODE", "PATHCODE"),
    ],
)
def test_extract_referral_code(raw: str | None, expected: str | None) -> None:
    """Bare codes and invite links normalize to a referral code."""
    assert extract_referral_code(raw) == expected


def test_normalize_birth_date_shamsi_and_iso() -> None:
    """Shamsi and Gregorian ISO both yield shamsi str + gregorian date."""
    shamsi, gregorian = normalize_birth_date("1370/01/15")
    assert shamsi == "1370/01/15"
    assert isinstance(gregorian, date)

    shamsi2, gregorian2 = normalize_birth_date("1991-04-04")
    assert gregorian2 == date(1991, 4, 4)
    assert "/" in shamsi2


def test_normalize_birth_date_invalid() -> None:
    """Invalid birth dates raise BadRequestError with error_code."""
    with pytest.raises(BadRequestError) as exc:
        normalize_birth_date("not-a-date")
    assert exc.value.error_code == "invalid_birth_date"


def test_resolve_acr_and_signing_level() -> None:
    """ACR/signing_level map from AMR strength."""
    assert resolve_acr(["password"]) == ACR_BASIC
    assert resolve_acr(["password", "totp"]) == ACR_MFA
    assert resolve_acr(["totp"]) == ACR_MFA
    assert resolve_signing_level(["webauthn"]) == "hardware"
    assert resolve_signing_level(["magic_link"]) == "software"
    assert resolve_signing_level(["password"]) is None


def test_api_key_ip_whitelist() -> None:
    """Non-empty IP allowlist rejects other client IPs."""
    key = MagicMock(ip_whitelist=["1.2.3.4"])
    api_key_services.enforce_api_key_ip_whitelist(key, client_ip="1.2.3.4")
    with pytest.raises(ForbiddenError) as exc:
        api_key_services.enforce_api_key_ip_whitelist(key, client_ip="9.9.9.9")
    assert exc.value.error_code == "api_key_ip_denied"


@pytest.mark.asyncio
async def test_api_key_rate_limit_memory() -> None:
    """Per-key rate limit raises after the configured request count."""
    key = MagicMock(
        uid="rate-limit-unique-key",
        rate_limit={"requests": 2, "window_seconds": 60},
    )
    api_key_services._rate_buckets.clear()
    with patch("apps.identity.api_key.services.redis", None):
        await api_key_services.enforce_api_key_rate_limit(key)
        await api_key_services.enforce_api_key_rate_limit(key)
        with pytest.raises(TooManyRequestsError):
            await api_key_services.enforce_api_key_rate_limit(key)


def test_login_request_extracts_referral_from_link() -> None:
    """LoginRequest normalizes invite URLs into referral_code."""
    from apps.identity.auth.enums import AuthIdentifier
    from apps.identity.auth.schemas import LoginRequest

    req = LoginRequest(
        type=AuthIdentifier.EMAIL,
        identifier="a@b.com",
        referral_code="https://app/join?ref=FROMURL",
    )
    assert req.referral_code == "FROMURL"
