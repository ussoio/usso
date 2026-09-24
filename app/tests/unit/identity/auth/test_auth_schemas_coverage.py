"""Focused coverage for the convenience login body schemas."""

import pytest
from pydantic import ValidationError

from apps.identity.auth.auth_schemas import (
    ClientIDSecretLogin,
    EmailOtpLogin,
    EmailPasswordLogin,
    PhoneOtpLogin,
    PhonePasswordLogin,
    UsernameOtpLogin,
    UsernamePasswordLogin,
)
from apps.identity.auth.enums import AuthIdentifier, AuthSecret
from apps.identity.auth.schemas import SecureTokenRequest


@pytest.mark.parametrize(
    ("body", "identifier_type", "identifier", "method", "secret"),
    [
        (
            EmailPasswordLogin(email="USER@example.com", password="pw"),
            AuthIdentifier.EMAIL,
            "USER@example.com",
            AuthSecret.PASSWORD,
            "pw",
        ),
        (
            EmailOtpLogin(email="user@example.com", otp="123456"),
            AuthIdentifier.EMAIL,
            "user@example.com",
            AuthSecret.EMAIL_OTP,
            "123456",
        ),
        (
            PhoneOtpLogin(phone="09120000000", otp="654321"),
            AuthIdentifier.PHONE,
            "09120000000",
            AuthSecret.PHONE_OTP,
            "654321",
        ),
        (
            PhonePasswordLogin(phone="09120000000", password="pw"),
            AuthIdentifier.PHONE,
            "09120000000",
            AuthSecret.PASSWORD,
            "pw",
        ),
        (
            UsernamePasswordLogin(username="alice", password="pw"),
            AuthIdentifier.USERNAME,
            "alice",
            AuthSecret.PASSWORD,
            "pw",
        ),
        (
            UsernameOtpLogin(username="alice", otp="123456"),
            AuthIdentifier.USERNAME,
            "alice",
            AuthSecret.PHONE_OTP,
            "123456",
        ),
        (
            ClientIDSecretLogin(client_id="client-1", client_secret="secret"),
            AuthIdentifier.CLIENT_ID,
            "client-1",
            AuthSecret.CLIENT_SECRET,
            "secret",
        ),
    ],
)
def test_login_body_properties_and_login_request(
    body: object,
    identifier_type: AuthIdentifier,
    identifier: str,
    method: AuthSecret,
    secret: str,
) -> None:
    """Every convenience body maps its fields into a LoginRequest."""
    assert body.type == identifier_type
    assert body.identifier == identifier
    assert body.method == method
    assert body.secret == secret

    request = body.login_request
    assert request.type == identifier_type
    expected_request_identifier = (
        "989120000000" if identifier_type == AuthIdentifier.PHONE else identifier
    )
    assert request.identifier == expected_request_identifier
    assert request.method == method
    assert request.secret == secret


def test_email_login_rejects_invalid_email() -> None:
    """EmailStr validation remains active on the convenience schemas."""
    with pytest.raises(ValidationError):
        EmailPasswordLogin(email="not-an-email", password="pw")


def test_secure_token_request_forbids_referral_fields() -> None:
    """Step-up authentication must not accept registration-only metadata."""
    with pytest.raises(ValidationError):
        SecureTokenRequest(
            type=AuthIdentifier.PHONE,
            identifier="09120000000",
            method=AuthSecret.PHONE_OTP,
            secret="123456",
            referral_code="invite-code",
        )
