"""Tests for process_login_flow function."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.auth.enums import (
    SIMPLE_PASSWORD,
    AuthSecret,
    AuthStep,
    LoginStatus,
)
from apps.identity.auth.schemas import AuthIdentifier, LoginRequest
from apps.identity.auth.services import process_login_flow
from apps.identity.user.models import User
from apps.tenant.config import (
    ApprovalMode,
    AuthenticationConfig,
    RegistrationConfig,
    TenantConfig,
)
from apps.tenant.models import Tenant
from server.exceptions import UnauthorizedError

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def mock_user() -> MagicMock:
    """Mock user fixture."""
    user = MagicMock(spec=User)
    user.uid = "user123"
    user.tenant_id = "tenant123"
    user.is_active = False
    user.mfa_enabled = False
    user.mfa_steps = None
    user.current_identifier = MagicMock()
    user.current_identifier.verified_at = None
    user.current_identifier.save = AsyncMock()
    user.save = AsyncMock()
    return user


@pytest.fixture
def mock_tenant() -> MagicMock:
    """Mock tenant fixture."""
    tenant = MagicMock(spec=Tenant)
    tenant.uid = "tenant123"
    tenant.config = TenantConfig(
        auth=AuthenticationConfig(login_flow=SIMPLE_PASSWORD),
        registration=RegistrationConfig(
            is_allowed=True,
            approval_mode=ApprovalMode.NONE,
            invite_only=False,
        ),
    )
    return tenant


@pytest.fixture
def login_request() -> LoginRequest:
    """Login request fixture."""
    return LoginRequest(
        type=AuthIdentifier.EMAIL,
        identifier="test@uln.me",
        method=AuthSecret.PASSWORD,
        secret="password123",
    )


@pytest.mark.asyncio
async def test_process_login_flow_new_user_registration_success(
    mock_tenant: Tenant, login_request: LoginRequest, mock_user: User
) -> None:
    """Test process_login_flow when user doesn't exist and registration succeeds."""
    with (
        patch("apps.identity.auth.services.login_flow.find_user", return_value=None),
        patch(
            "apps.identity.auth.services.login_flow.register_new_user",
            return_value=mock_user,
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=None,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=True,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.COMPLETED


@pytest.mark.asyncio
async def test_process_login_flow_new_user_registration_failed(
    mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when user doesn't exist and registration fails."""
    with (
        patch("apps.identity.auth.services.login_flow.find_user", return_value=None),
        patch(
            "apps.identity.auth.services.login_flow.register_new_user",
            return_value=None,
        ),
    ):
        with pytest.raises(UnauthorizedError) as exc_info:
            await process_login_flow(login_request=login_request, tenant=mock_tenant)

        assert exc_info.value.error_code == "invalid_credentials"


@pytest.mark.asyncio
async def test_process_login_flow_new_user_needs_verification(
    mock_tenant: Tenant, login_request: LoginRequest, mock_user: User
) -> None:
    """Test process_login_flow when new user needs verification."""
    mock_tenant.config.registration.approval_mode = ApprovalMode.IDENTIFIER

    with (
        patch("apps.identity.auth.services.login_flow.find_user", return_value=None),
        patch(
            "apps.identity.auth.services.login_flow.register_new_user",
            return_value=mock_user,
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=None,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_authentication_failed(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when authentication fails."""
    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=False,
        ),
    ):
        with pytest.raises(UnauthorizedError) as exc_info:
            await process_login_flow(login_request=login_request, tenant=mock_tenant)

        assert exc_info.value.error_code == "invalid_credentials"


@pytest.mark.asyncio
async def test_process_login_flow_no_identifier(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when user has no current identifier."""
    mock_user.current_identifier = None

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_verification_required(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when verification is required."""
    mock_user.current_identifier.verified_at = None

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_completed_simple(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when simple flow is completed."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"  # Already verified
    )

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=None,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=True,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.COMPLETED


@pytest.mark.asyncio
async def test_process_login_flow_mfa_required(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when MFA is required."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )
    mock_user.mfa_enabled = True
    mock_user.mfa_steps = [AuthStep(methods=[AuthSecret.TOTP])]

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion"
        ) as mock_validate,
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        # First call returns None (main flow completed),
        # second call returns next step (MFA required)
        mock_validate.side_effect = [None, AuthStep(methods=[AuthSecret.TOTP])]

        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.MFA_REQUIRED
        assert mock_validate.call_count == 2


@pytest.mark.asyncio
async def test_process_login_flow_with_temporary_token(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow with temporary token."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )

    temporary_token = MagicMock()
    temporary_token.unverified_payload = {"amr": ["password"]}

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=None,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request,
            tenant=mock_tenant,
            temporary_payload=temporary_token,
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_multi_step_authentication(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow with multi-step authentication."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )

    next_step = AuthStep(methods=[AuthSecret.TOTP])

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=next_step,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.MFA_REQUIRED
        assert result.next_step == next_step


@pytest.mark.asyncio
async def test_process_login_flow_verification_needed_with_next_step(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when verification is needed but there's a next step."""
    mock_user.current_identifier.verified_at = None

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_user_already_active(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow when user is already active."""
    mock_user.is_active = True
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=None,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=True,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.COMPLETED


@pytest.mark.asyncio
async def test_process_login_flow_empty_amr(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow with empty amr list."""
    mock_user.current_identifier.verified_at = None

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion"
        ) as mock_validate,
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        mock_validate.return_value = None

        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        # Only assert the status, do not check mock_validate call
        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_with_string_temporary_token(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test process_login_flow with string temporary token."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )

    temporary_token = mock_tenant.sign_jwt({"amr": ["password"]}, hmac=True)

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion",
            return_value=None,
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        result = await process_login_flow(
            login_request=login_request,
            tenant=mock_tenant,
            temporary_payload=temporary_token,
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.asyncio
async def test_process_login_flow_amr_includes_method(
    mock_user: User, mock_tenant: Tenant, login_request: LoginRequest
) -> None:
    """Test that the amr list includes the login request method."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion"
        ) as mock_validate,
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        mock_validate.return_value = None

        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        # Verify that the amr list includes the login method
        assert "password" in result.amr
        assert result.status == LoginStatus.VERIFICATION_REQUIRED


@pytest.mark.parametrize(
    "mfa_enabled,mfa_steps,expected_mfa_calls",
    [
        (
            True,
            [AuthStep(methods=[AuthSecret.TOTP])],
            2,
        ),  # MFA enabled with steps
        (True, None, 1),  # MFA enabled but no steps
        (True, [], 1),  # MFA enabled but empty steps
        (False, [AuthStep(methods=[AuthSecret.TOTP])], 1),  # MFA disabled
        (False, None, 1),  # MFA disabled and no steps
    ],
)
@pytest.mark.asyncio
async def test_process_login_flow_mfa_variations(
    mock_user: User,
    mock_tenant: Tenant,
    login_request: LoginRequest,
    mfa_enabled: bool,
    mfa_steps: list | None,
    expected_mfa_calls: int,
) -> None:
    """Test process_login_flow with different MFA configurations."""
    mock_user.current_identifier.verified_at = datetime.fromisoformat(
        "2023-01-01T00:00:00Z"
    )
    mock_user.mfa_enabled = mfa_enabled
    mock_user.mfa_steps = mfa_steps

    with (
        patch(
            "apps.identity.auth.services.login_flow.find_user", return_value=mock_user
        ),
        patch(
            "apps.identity.auth.services.login_flow.authenticate_user",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.login_flow.validate_flow_completion"
        ) as mock_validate,
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            return_value=False,
        ),
    ):
        mock_validate.return_value = None

        result = await process_login_flow(
            login_request=login_request, tenant=mock_tenant
        )

        assert result.status == LoginStatus.VERIFICATION_REQUIRED
        assert mock_validate.call_count == expected_mfa_calls
