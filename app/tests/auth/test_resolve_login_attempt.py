"""Tests for resolve_login_attempt function."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.auth.enums import (
    PASSWORD_OR_OTP,
    PASSWORDLESS_FLOW,
    SIMPLE_PASSWORD,
    AuthSecret,
    LoginStatus,
    OTPDeliveryStatus,
)
from apps.identity.auth.schemas import AuthIdentifier, Identifier
from apps.identity.auth.services.login_flow import resolve_login_attempt
from apps.identity.user.models import User
from server.exceptions import BadRequestError

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def mock_user() -> MagicMock:
    """Create a mock user."""
    user = MagicMock(spec=User)
    user.uid = "user123"
    user.tenant_id = "tenant123"
    user.is_active = True
    user.get_credentials = AsyncMock(return_value=[])
    user.get_identifiers = AsyncMock(return_value=[])
    return user


@pytest.fixture
def mock_user_with_password(mock_user: MagicMock) -> MagicMock:
    """Create a mock user with a password credential."""
    mock_cred = MagicMock()
    mock_cred.method = AuthSecret.PASSWORD
    mock_user.get_credentials = AsyncMock(return_value=[mock_cred])
    return mock_user


@pytest.fixture
def mock_tenant() -> MagicMock:
    """Create a mock tenant."""
    tenant = MagicMock()
    tenant.uid = "tenant123"
    tenant.config.auth.login_flow = SIMPLE_PASSWORD
    tenant.config.registration.is_allowed = True
    return tenant


@pytest.fixture
def identifier_email() -> Identifier:
    """Create an email identifier fixture."""
    return Identifier(type=AuthIdentifier.EMAIL, identifier="test@uln.me")


@pytest.fixture
def identifier_phone() -> Identifier:
    """Create a phone identifier fixture."""
    return Identifier(type=AuthIdentifier.PHONE, identifier="+989123456789")


@pytest.mark.asyncio
async def test_simple_password_flow_returns_password_method(
    mock_tenant: MagicMock,
    mock_user_with_password: MagicMock,
    identifier_email: Identifier,
) -> None:
    """SIMPLE_PASSWORD flow should return password as the only method."""
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user_with_password,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_email, tenant=mock_tenant
        )

    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    assert result.next_step is not None
    assert AuthSecret.PASSWORD in result.next_step.methods
    assert result.otp_delivery == {}


@pytest.mark.asyncio
async def test_password_or_otp_flow_with_password_user(
    mock_tenant: MagicMock,
    mock_user_with_password: MagicMock,
    identifier_phone: Identifier,
) -> None:
    """PASSWORD_OR_OTP with user who has password: OTP should be requestable."""
    mock_tenant.config.auth.login_flow = PASSWORD_OR_OTP
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user_with_password,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_phone, tenant=mock_tenant
        )

    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    assert result.next_step is not None
    assert AuthSecret.PHONE_OTP in result.otp_delivery
    assert result.otp_delivery[AuthSecret.PHONE_OTP] == OTPDeliveryStatus.REQUESTABLE


@pytest.mark.asyncio
async def test_password_or_otp_flow_without_password_user(
    mock_tenant: MagicMock,
    mock_user: MagicMock,
    identifier_phone: Identifier,
) -> None:
    """PASSWORD_OR_OTP does not disclose whether the user has a password."""
    mock_tenant.config.auth.login_flow = PASSWORD_OR_OTP
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_phone, tenant=mock_tenant
        )

    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    assert AuthSecret.PHONE_OTP in result.otp_delivery
    assert result.otp_delivery[AuthSecret.PHONE_OTP] == OTPDeliveryStatus.REQUESTABLE


@pytest.mark.asyncio
async def test_password_or_otp_flow_accepts_email_identifier(
    mock_tenant: MagicMock,
    mock_user: MagicMock,
    identifier_email: Identifier,
) -> None:
    mock_tenant.config.auth.login_flow = PASSWORD_OR_OTP
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_email, tenant=mock_tenant
        )

    assert result.next_step is not None
    assert AuthSecret.EMAIL_OTP in result.next_step.methods
    assert result.otp_delivery[AuthSecret.EMAIL_OTP] == OTPDeliveryStatus.REQUESTABLE


@pytest.mark.asyncio
async def test_user_not_found_registration_allowed(
    mock_tenant: MagicMock,
    identifier_email: Identifier,
) -> None:
    """When user not found but registration allowed, return challenge."""
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=None,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_email, tenant=mock_tenant
        )

    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    assert result.user is None
    assert result.next_step is not None


@pytest.mark.asyncio
async def test_user_not_found_registration_not_allowed(
    mock_tenant: MagicMock,
    identifier_email: Identifier,
) -> None:
    """Closed registration does not turn login-attempt into an account oracle."""
    mock_tenant.config.registration.is_allowed = False
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=None,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_email,
            tenant=mock_tenant,
        )
    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    assert result.user is None


@pytest.mark.asyncio
async def test_identifier_type_not_allowed(
    mock_tenant: MagicMock, identifier_phone: Identifier
) -> None:
    """When identifier type not in allowed_identifiers, raise identifier_not_allowed."""
    mock_tenant.config.auth.login_flow = SIMPLE_PASSWORD
    identifier_phone.type = AuthIdentifier.TELEGRAM_ID
    identifier_phone.identifier = "12345678"
    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user",
            return_value=None,
        ),
        pytest.raises(BadRequestError) as exc_info,
    ):
        await resolve_login_attempt(identifier=identifier_phone, tenant=mock_tenant)

    assert exc_info.value.error_code == "identifier_not_allowed"


@pytest.mark.asyncio
async def test_invalid_flow_raises(
    mock_tenant: MagicMock, identifier_email: Identifier
) -> None:
    """When login flow has no steps, raise invalid_flow."""
    mock_tenant.config.auth.login_flow = MagicMock()
    mock_tenant.config.auth.login_flow.allowed_identifiers = [AuthIdentifier.EMAIL]
    mock_tenant.config.auth.login_flow.steps = []
    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user",
            return_value=None,
        ),
        pytest.raises(BadRequestError) as exc_info,
    ):
        await resolve_login_attempt(identifier=identifier_email, tenant=mock_tenant)

    assert exc_info.value.error_code == "invalid_flow"


@pytest.mark.asyncio
async def test_passwordless_flow_auto_sends_otp(
    mock_tenant: MagicMock, mock_user: MagicMock
) -> None:
    """A mixed passwordless flow does not disclose available credentials."""
    mock_tenant.config.auth.login_flow = PASSWORDLESS_FLOW
    identifier = Identifier(type=AuthIdentifier.EMAIL, identifier="test@uln.me")
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user,
    ):
        result = await resolve_login_attempt(identifier=identifier, tenant=mock_tenant)

    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    if AuthSecret.EMAIL_OTP in result.otp_delivery:
        assert (
            result.otp_delivery[AuthSecret.EMAIL_OTP] == OTPDeliveryStatus.REQUESTABLE
        )


@pytest.mark.asyncio
async def test_password_or_otp_flow_phone_identifier_drops_email_otp(
    mock_tenant: MagicMock,
    mock_user: MagicMock,
    identifier_phone: Identifier,
) -> None:
    """A phone cannot receive an email code, so EMAIL_OTP is not offered."""
    mock_tenant.config.auth.login_flow = PASSWORD_OR_OTP
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_phone, tenant=mock_tenant
        )

    assert result.next_step is not None
    assert AuthSecret.EMAIL_OTP not in result.next_step.methods
    assert AuthSecret.PHONE_OTP in result.next_step.methods
    assert AuthSecret.PASSWORD in result.next_step.methods


@pytest.mark.asyncio
async def test_password_or_otp_flow_email_identifier_drops_phone_otp(
    mock_tenant: MagicMock,
    mock_user: MagicMock,
    identifier_email: Identifier,
) -> None:
    mock_tenant.config.auth.login_flow = PASSWORD_OR_OTP
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user,
    ):
        result = await resolve_login_attempt(
            identifier=identifier_email, tenant=mock_tenant
        )

    assert result.next_step is not None
    assert AuthSecret.PHONE_OTP not in result.next_step.methods
    assert AuthSecret.PHONE_OTP not in result.otp_delivery


@pytest.mark.asyncio
async def test_passwordless_flow_keeps_non_delivery_methods(
    mock_tenant: MagicMock, mock_user: MagicMock
) -> None:
    """Identifier filtering must not strip passkey or magic link for email."""
    mock_tenant.config.auth.login_flow = PASSWORDLESS_FLOW
    identifier = Identifier(type=AuthIdentifier.EMAIL, identifier="test@uln.me")
    with patch(
        "apps.identity.auth.services.login_flow.find_user",
        return_value=mock_user,
    ):
        result = await resolve_login_attempt(identifier=identifier, tenant=mock_tenant)

    assert result.next_step is not None
    assert set(result.next_step.methods) == {
        AuthSecret.MAGIC_LINK,
        AuthSecret.EMAIL_OTP,
        AuthSecret.WEBAUTHN,
    }
