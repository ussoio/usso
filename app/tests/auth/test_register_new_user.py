"""Tests for register_new_user function."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pymongo.errors import DuplicateKeyError

from apps.identity.auth.schemas import LoginRequest
from apps.identity.auth.services import register_new_user
from apps.identity.user.models import User
from apps.tenant.config import RegistrationConfig, TenantConfig
from apps.tenant.models import Tenant

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def mock_user() -> MagicMock:
    """Mock user fixture."""
    user = MagicMock(spec=User)
    user.uid = "user123"
    user.tenant_id = "tenant123"
    user.is_active = False
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
        registration=RegistrationConfig(is_allowed=True, invite_only=False),
    )
    return tenant


@pytest.fixture
def login_request_data() -> dict:
    """Login request fixture."""
    return {
        "type": "email",
        "identifier": "test@uln.me",
        "method": "password",
        "secret": "password123",
    }


@pytest.mark.asyncio
async def test_register_new_user_success(
    mock_tenant: Tenant, login_request_data: dict, mock_user: User
) -> None:
    """Test register_new_user when registration is successful."""
    login_request = LoginRequest(**login_request_data)
    with patch(
        "apps.identity.auth.services.login_flow.create_user", return_value=mock_user
    ):
        user = await register_new_user(login_request=login_request, tenant=mock_tenant)

        assert user is not None
        assert user.uid == "user123"


@pytest.mark.asyncio
async def test_register_new_user_registration_closed(
    mock_tenant: Tenant, login_request_data: dict
) -> None:
    """Test register_new_user when registration is closed."""
    mock_tenant.config.registration.is_allowed = False
    login_request = LoginRequest(**login_request_data)

    result = await register_new_user(login_request=login_request, tenant=mock_tenant)

    assert result is None


@pytest.mark.asyncio
async def test_register_new_user_calls_create_user(
    mock_tenant: Tenant, login_request_data: dict, mock_user: User
) -> None:
    """Test that register_new_user calls create_user with correct parameters."""
    login_request = LoginRequest(**login_request_data)

    with patch("apps.identity.auth.services.login_flow.create_user") as mock_create:
        mock_create.return_value = mock_user

        await register_new_user(login_request=login_request, tenant=mock_tenant)

        # Verify create_user was called with correct parameters
        mock_create.assert_called_once_with(
            login=login_request, tenant=mock_tenant, audit_as_self=True
        )


@pytest.mark.asyncio
async def test_register_new_user_returns_user_object(
    mock_tenant: Tenant, login_request_data: dict, mock_user: User
) -> None:
    """Test that register_new_user returns the user object created by create_user."""
    login_request = LoginRequest(**login_request_data)
    expected_user = mock_user

    with patch(
        "apps.identity.auth.services.login_flow.create_user", return_value=expected_user
    ):
        result = await register_new_user(
            login_request=login_request, tenant=mock_tenant
        )

        assert result is expected_user


@pytest.mark.asyncio
async def test_register_new_user_handles_create_user_exception(
    mock_tenant: Tenant, login_request_data: dict
) -> None:
    """Test that register_new_user properly handles exceptions from create_user."""
    login_request = LoginRequest(**login_request_data)

    with patch(
        "apps.identity.auth.services.login_flow.create_user",
        side_effect=Exception("Database error"),
    ):
        with pytest.raises(Exception) as exc_info:
            await register_new_user(login_request=login_request, tenant=mock_tenant)

        assert "Database error" in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_register_duplicate_user(
    mock_tenant: Tenant, login_request_data: dict, mock_user: User
) -> None:
    login_request = LoginRequest(**login_request_data)
    u1 = await register_new_user(login_request=login_request, tenant=mock_tenant)

    with pytest.raises(DuplicateKeyError):
        await register_new_user(login_request=login_request, tenant=mock_tenant)

    assert u1 is not None
    assert u1.tenant_id == mock_tenant.uid
    assert u1.is_active is False
    assert u1.current_identifier.verified_at is None
