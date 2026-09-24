"""Unit tests for secure session token helpers."""

from unittest.mock import MagicMock

from usso.user import TokenType

from apps.identity.auth.enums import AuthSecret
from apps.identity.auth.services.secure_token import (
    create_secure_token_payload,
    is_secure_amr,
    is_secure_method,
)


def test_is_secure_amr_accepts_otp_and_totp() -> None:
    """OTP/TOTP/magic-link AMRs qualify as secure."""
    assert is_secure_amr(["password", "phone/otp"])
    assert is_secure_amr(["totp"])
    assert is_secure_amr(["magic_link"])
    assert not is_secure_amr(["password"])
    assert not is_secure_amr([])
    assert not is_secure_amr(None)


def test_is_secure_method() -> None:
    """Method enum and string forms are recognized."""
    assert is_secure_method(AuthSecret.PHONE_OTP)
    assert is_secure_method("email/otp")
    assert not is_secure_method(AuthSecret.PASSWORD)
    assert not is_secure_method(None)


def test_create_secure_token_payload_uses_session_timeout() -> None:
    """Secure token TTL comes from tenant secure_session_timeout."""
    user = MagicMock()
    user.uid = "user-1"
    user.tenant_id = "tenant-1"

    tenant = MagicMock()
    tenant.primary_url = "https://example.test"
    tenant.config.token.get_timeout.return_value = 600
    tenant.sign_jwt.side_effect = lambda payload, **_: "signed"

    payload = create_secure_token_payload(
        user=user,
        tenant=tenant,
        amr=["phone/otp"],
    )

    tenant.config.token.get_timeout.assert_called_with("secure")
    assert payload.token_type == TokenType.SECURE_TOKEN
    assert payload.sub == "user-1"
    assert payload.amr == ["phone/otp"]
    assert payload.exp - payload.iat == 600
    assert payload.token == "signed"
    tenant.sign_jwt.assert_called_once()
    assert tenant.sign_jwt.call_args.kwargs.get("hmac") is True
