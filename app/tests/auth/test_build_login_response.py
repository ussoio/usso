"""Tests for build_login_response function."""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from usso.user import TokenType

from apps.identity.auth.enums import LoginStatus
from apps.identity.auth.schemas import PayloadData
from apps.identity.auth.services import build_login_response
from apps.tenant.config import TenantConfig, TenantCookieHeaderConfig
from apps.tenant.models import Tenant

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def mock_request() -> MagicMock:
    """Create a mock request."""
    request = MagicMock(spec=Request)
    # Mock properties properly
    type(request).cookies = MagicMock(return_value={})
    type(request).headers = MagicMock(return_value={})
    # Set up URL structure to avoid MagicMock in domain parameter
    request.url = MagicMock()
    request.url.hostname = "example.com"
    return request


@pytest.fixture
def mock_tenant() -> MagicMock:
    """Create a mock tenant."""
    tenant = MagicMock(spec=Tenant)
    tenant.primary_domain = "example.com"
    tenant.domains = ["example.com", "app.example.com"]
    tenant.config = TenantConfig(
        cookie_header_config=TenantCookieHeaderConfig(header_or_cookie="cookie"),
    )
    return tenant


@pytest.fixture
def sample_payloads() -> dict:
    """Create sample token payloads."""
    now = 1640995200  # 2022-01-01 00:00:00 UTC

    access_payload = PayloadData(
        jti="test-jti-123",
        token_type=TokenType.ACCESS,
        iss="example.com",
        aud="test-audience",
        iat=now,
        nbf=now,
        exp=now + 3600,
        sub="user-123",
        tenant_id="tenant-123",
        session_id="session-123",
        workspace_id="workspace-123",
        roles=["user"],
        scopes=["read", "write"],
        amr=["password"],
        acr="1",
        signing_level="standard",
        claims={"name": "Test User"},
    )
    access_payload.token = "access-token-123"

    refresh_payload = PayloadData(
        jti="test-jti-123",
        token_type=TokenType.REFRESH,
        iss="example.com",
        aud="test-audience",
        iat=now,
        nbf=now,
        exp=now + 86400,
        sub="user-123",
        tenant_id="tenant-123",
        session_id="session-123",
        workspace_id="workspace-123",
        roles=["user"],
        scopes=["read", "write"],
        amr=["password"],
        acr="1",
        signing_level="standard",
        claims={"name": "Test User"},
    )
    refresh_payload.token = "refresh-token-123"

    return {
        TokenType.ACCESS: access_payload,
        TokenType.REFRESH: refresh_payload,
    }


def test_build_login_response_with_cookies(
    mock_request: Request, mock_tenant: Tenant, sample_payloads: dict
) -> None:
    """Test build_login_response when cookies are preferred."""
    # Setup request to prefer cookies
    with (
        patch.object(mock_request, "cookies", {"existing": "cookie"}),
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.token.attach_auth_cookies_to_response"
        ) as mock_attach,
    ):
        result = build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=sample_payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
        )

    # Verify response is a JSONResponse
    assert isinstance(result, JSONResponse)

    # Verify response body contains the expected data
    response_data = json.loads(bytes(result.body).decode())

    # Check that tokens are NOT included when cookies are preferred
    assert "tokens" not in response_data

    # Check that user data is included
    assert response_data["jti"] == "test-jti-123"
    assert response_data["sub"] == "user-123"
    assert response_data["tenant_id"] == "tenant-123"
    assert response_data["name"] == "Test User"  # from claims

    # Verify cookies were attached
    mock_attach.assert_called_once_with(
        response=result,
        tenant=mock_tenant,
        payloads=sample_payloads,
        domain="example.com",  # Uses request.url.hostname when domain is None
    )


def test_build_login_response_without_cookies(
    mock_request: Request, mock_tenant: Tenant, sample_payloads: dict
) -> None:
    """Test build_login_response when cookies are not preferred."""
    # Setup request to not prefer cookies
    with (
        patch.object(mock_request, "cookies", {"existing": "cookie"}),
        patch.object(mock_request, "headers", {"user-agent": "curl/7.68.0"}),
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=False,
        ),
        patch(
            "apps.identity.auth.services.token.attach_auth_cookies_to_response"
        ) as mock_attach,
    ):
        result = build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=sample_payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
        )

    # Verify response is a JSONResponse
    assert isinstance(result, JSONResponse)

    # Verify response body contains the expected data
    response_data = json.loads(bytes(result.body).decode())

    # Check that tokens are included when cookies are not preferred
    assert "tokens" in response_data
    assert response_data["tokens"]["access"] == "access-token-123"
    assert response_data["tokens"]["refresh"] == "refresh-token-123"

    # Check that user data is included
    assert response_data["jti"] == "test-jti-123"
    assert response_data["sub"] == "user-123"
    assert response_data["tenant_id"] == "tenant-123"
    assert response_data["name"] == "Test User"  # from claims

    # Verify cookies were NOT attached
    mock_attach.assert_not_called()


def test_build_login_response_with_domain(
    mock_request: Request, mock_tenant: Tenant, sample_payloads: dict
) -> None:
    """Test build_login_response with custom domain."""
    # Setup request to prefer cookies
    mock_request.cookies = {"existing": "cookie"}

    with (
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=True,
        ),
        patch(
            "apps.identity.auth.services.token.attach_auth_cookies_to_response"
        ) as mock_attach,
    ):
        result = build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=sample_payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
            domain="app.example.com",
        )

    # Verify cookies were attached with custom domain
    mock_attach.assert_called_once_with(
        response=result,
        tenant=mock_tenant,
        payloads=sample_payloads,
        domain="app.example.com",
    )


def test_build_login_response_single_token(
    mock_request: Request, mock_tenant: Tenant
) -> None:
    """Test build_login_response with only one token type."""
    now = 1640995200  # 2022-01-01 00:00:00 UTC

    single_payload = PayloadData(
        jti="test-jti-123",
        token_type=TokenType.TEMPORARY_TOKEN,
        iss="example.com",
        aud="test-audience",
        iat=now,
        nbf=now,
        exp=now + 300,
        sub="user-123",
        tenant_id="tenant-123",
        session_id=None,
        workspace_id="workspace-123",
        roles=["user"],
        scopes=["read"],
        amr=["password"],
        acr="1",
        signing_level="standard",
        claims={"name": "Test User"},
    )
    single_payload.token = "temp-token-123"

    payloads = {TokenType.TEMPORARY_TOKEN: single_payload}

    with patch(
        "apps.identity.auth.services.token.is_cookie_auth_preferred",
        return_value=False,
    ):
        result = build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
        )

    # Verify response is a JSONResponse
    assert isinstance(result, JSONResponse)

    # Verify response body contains the expected data
    response_data = json.loads(bytes(result.body).decode())

    # Check that token is included - use the enum value as key
    assert "tokens" in response_data
    # The key should be the enum value, not the enum name
    token_key = TokenType.TEMPORARY_TOKEN.value
    assert response_data["tokens"][token_key] == "temp-token-123"

    # Check that user data is included
    assert response_data["jti"] == "test-jti-123"
    assert response_data["sub"] == "user-123"
    assert response_data["tenant_id"] == "tenant-123"
    assert response_data["name"] == "Test User"  # from claims


def test_build_login_response_empty_payloads(
    mock_request: Request, mock_tenant: Tenant
) -> None:
    """Test build_login_response with empty payloads."""
    with (
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=False,
        ),
        pytest.raises(StopIteration),
    ):
        build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads={},
            status=LoginStatus.COMPLETED,
            next_step=None,
        )


def test_build_login_response_json_serialization(
    mock_request: Request, mock_tenant: Tenant, sample_payloads: dict
) -> None:
    """Test that the response body is properly JSON serialized."""
    with patch(
        "apps.identity.auth.services.token.is_cookie_auth_preferred",
        return_value=False,
    ):
        result = build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=sample_payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
        )

    # Verify response is a JSONResponse
    assert isinstance(result, JSONResponse)

    # Verify response body is valid JSON
    response_data = json.loads(bytes(result.body).decode())

    # Check structure
    assert "tokens" in response_data
    assert "access" in response_data["tokens"]
    assert "refresh" in response_data["tokens"]
    assert response_data["tokens"]["access"] == "access-token-123"
    assert response_data["tokens"]["refresh"] == "refresh-token-123"

    # Check other fields
    assert response_data["jti"] == "test-jti-123"
    assert response_data["sub"] == "user-123"
    assert response_data["tenant_id"] == "tenant-123"
    assert "name" in response_data  # from claims
    assert response_data["name"] == "Test User"


def test_build_login_response_cookie_preference_detection(
    mock_request: Request, mock_tenant: Tenant, sample_payloads: dict
) -> None:
    """Test that cookie preference is properly detected."""
    # Test with cookies present
    with (
        patch.object(mock_request, "cookies", {"session": "abc123"}),
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=True,
        ) as mock_detect,
    ):
        with patch("apps.identity.auth.services.token.attach_auth_cookies_to_response"):
            build_login_response(
                request=mock_request,
                tenant=mock_tenant,
                payloads=sample_payloads,
                status=LoginStatus.COMPLETED,
                next_step=None,
            )

        # The function calls is_cookie_auth_preferred twice
        # once for the condition and once for the cookies
        assert mock_detect.call_count == 2
        mock_detect.assert_any_call(request=mock_request, tenant_cookie=True)

    # Test with browser user agent
    with (
        patch.object(mock_request, "cookies", {"existing": "cookie"}),
        patch.object(
            mock_request,
            "headers",
            {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        ),
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=True,
        ) as mock_detect,
        patch("apps.identity.auth.services.token.attach_auth_cookies_to_response"),
    ):
        build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=sample_payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
        )

        # The function calls is_cookie_auth_preferred twice
        assert mock_detect.call_count == 2
        mock_detect.assert_any_call(request=mock_request, tenant_cookie=True)


def test_build_login_response_uses_first_payload_for_base_data(
    mock_request: Request, mock_tenant: Tenant
) -> None:
    """Test that build_login_response uses the first payload for base response data."""
    # Create two different payloads
    payload1 = PayloadData(
        jti="first-jti",
        token_type=TokenType.ACCESS,
        sub="user-1",
        tenant_id="tenant-1",
        claims={"name": "First User"},
    )
    payload1.token = "token-1"

    payload2 = PayloadData(
        jti="second-jti",
        token_type=TokenType.REFRESH,
        sub="user-2",
        tenant_id="tenant-2",
        claims={"name": "Second User"},
    )
    payload2.token = "token-2"

    # Order matters - first payload should be used for base data
    payloads = {TokenType.ACCESS: payload1, TokenType.REFRESH: payload2}

    with patch(
        "apps.identity.auth.services.token.is_cookie_auth_preferred",
        return_value=False,
    ):
        result = build_login_response(
            request=mock_request,
            tenant=mock_tenant,
            payloads=payloads,
            status=LoginStatus.COMPLETED,
            next_step=None,
        )

    response_data = json.loads(bytes(result.body).decode())

    # Should use data from first payload (ACCESS token)
    assert response_data["jti"] == "first-jti"
    assert response_data["sub"] == "user-1"
    assert response_data["tenant_id"] == "tenant-1"
    assert response_data["name"] == "First User"

    # But tokens should include both
    assert response_data["tokens"]["access"] == "token-1"
    assert response_data["tokens"]["refresh"] == "token-2"
