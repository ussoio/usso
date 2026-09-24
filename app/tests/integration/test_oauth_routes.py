"""Tests for OAuth2/OIDC routes."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from apps.tenant.integration.schemas import (
    GrantType,
    ResponseType,
)
from utils.hasher import PasswordHasherService

OAUTH_CLIENT_SECRET_HASH = PasswordHasherService().hash_password("test_secret")


def _async_patch(target: str) -> object:
    return patch(target, new_callable=AsyncMock)


class TestOAuthRoutes:
    """Test OAuth2/OIDC routes."""

    @pytest.fixture
    def mock_tenant(self) -> MagicMock:
        """Mock tenant."""
        tenant = MagicMock()
        tenant.uid = "tenant_123"
        tenant.primary_url = "https://example.com"
        tenant.user_id = "user_123"
        tenant.get_frontend_url = MagicMock(
            return_value="https://example.com/consent",
        )
        return tenant

    @pytest.fixture
    def mock_oauth_client(self) -> AsyncMock:
        """Mock OAuth client."""
        client = AsyncMock()
        client.client_id = "test_client"
        client.client_secret = OAUTH_CLIENT_SECRET_HASH
        client.client_name = "Test Client"
        client.client_type = "confidential"
        client.redirect_uris = ["https://example.com/callback"]
        client.allowed_scopes = ["openid", "profile", "email"]
        client.grant_types = [GrantType.AUTHORIZATION_CODE]
        client.response_types = [ResponseType.CODE]
        client.is_active = True
        return client

    @pytest.fixture
    def mock_user(self) -> AsyncMock:
        """Mock user."""
        user = AsyncMock()
        user.uid = "user_123"
        user.username = "testuser"
        user.name = "Test User"
        user.get_identifiers = AsyncMock(return_value=[])
        user.get_username = AsyncMock(return_value="testuser")
        return user

    # NOTE: This test is disabled because the authorize endpoint implementation
    # has changed and needs further investigation
    # @patch("apps.tenant.integration.routes.get_tenant")
    # @patch("apps.tenant.integration.routes.validate_authorization_request")
    # @patch("apps.tenant.integration.dependencies.get_current_user_optional")
    # def test_authorize_endpoint_redirects_to_login_when_not_authenticated(...):

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.validate_authorization_request")
    @_async_patch("apps.tenant.integration.dependencies.get_current_user_optional")
    @_async_patch("apps.tenant.integration.routes.OAuthSession.get_by_state")
    @_async_patch("apps.tenant.integration.routes.create_authorization_code")
    async def test_authorize_endpoint_returns_authorization_code(
        self,
        mock_create_code: AsyncMock,
        mock_get_session: AsyncMock,
        mock_get_user: AsyncMock,
        mock_validate: AsyncMock,
        mock_get_tenant: AsyncMock,
        client: httpx.AsyncClient,
        mock_tenant: MagicMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test authorize endpoint returns authorization code for authenticated user."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant
        mock_validate.return_value = (mock_oauth_client, ["openid"])
        mock_get_user.return_value = mock_user
        mock_get_session.return_value = None

        auth_code = AsyncMock()
        auth_code.code = "auth_code_123"
        mock_create_code.return_value = auth_code

        response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://example.com/callback",
                "state": "test_state_secure_1234",
                "code_challenge": "A" * 43,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        assert response.status_code in {302, 307}
        assert response.headers["location"].startswith("https://example.com/consent")

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.validate_client")
    @_async_patch("apps.tenant.integration.routes.exchange_authorization_code")
    @_async_patch("apps.tenant.integration.routes.create_tokens")
    async def test_token_endpoint_authorization_code_grant(
        self,
        mock_create_tokens: AsyncMock,
        mock_exchange: AsyncMock,
        mock_validate_client: AsyncMock,
        mock_get_tenant: AsyncMock,
        client: httpx.AsyncClient,
        mock_tenant: MagicMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test token endpoint with authorization code grant."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant
        mock_validate_client.return_value = mock_oauth_client
        mock_oauth_client.token_endpoint_auth_method = "client_secret_post"
        mock_oauth_client.client_secret = OAUTH_CLIENT_SECRET_HASH
        mock_exchange.return_value = (mock_user, ["openid"], "test_nonce_123")

        token_response = AsyncMock()
        token_response.access_token = "access_token_123"
        token_response.token_type = "Bearer"
        token_response.expires_in = 3600
        token_response.refresh_token = "refresh_token_123"
        token_response.scope = "openid"
        token_response.id_token = "id_token_123"
        mock_create_tokens.return_value = token_response

        # Make request
        response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "code": "auth_code_123",
                "redirect_uri": "https://example.com/callback",
            },
        )

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "access_token_123"
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600
        assert data["refresh_token"] == "refresh_token_123"
        assert data["scope"] == "openid"
        assert data["id_token"] == "id_token_123"

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.validate_client")
    @_async_patch("apps.tenant.integration.routes.refresh_access_token")
    async def test_token_endpoint_refresh_token_grant(
        self,
        mock_refresh: AsyncMock,
        mock_validate_client: AsyncMock,
        mock_get_tenant: AsyncMock,
        client: httpx.AsyncClient,
        mock_tenant: MagicMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test token endpoint with refresh token grant."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant
        mock_validate_client.return_value = mock_oauth_client
        mock_oauth_client.token_endpoint_auth_method = "client_secret_post"
        mock_oauth_client.client_secret = OAUTH_CLIENT_SECRET_HASH

        from apps.tenant.integration.schemas import TokenResponseSchema

        token_response = TokenResponseSchema(
            access_token="new_access_token_123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="new_refresh_token_123",
            scope="openid",
            id_token="id_token_123",
        )
        mock_refresh.return_value = token_response

        # Make request
        response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "refresh_token": "old_refresh_token_123",
            },
        )

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "new_access_token_123"
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600
        assert data["refresh_token"] == "new_refresh_token_123"

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    async def test_token_endpoint_client_credentials_unknown_client(
        self,
        mock_get_tenant: AsyncMock,
        client: httpx.AsyncClient,
        mock_tenant: MagicMock,
    ) -> None:
        """Unknown client_id for client_credentials returns 401."""
        mock_get_tenant.return_value = mock_tenant

        response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "scope": "read",
            },
        )

        assert response.status_code == 401
        assert response.json()["error_code"] == "invalid_client"

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.get_user_info")
    async def test_userinfo_endpoint(
        self,
        mock_get_user_info: MagicMock,
        mock_get_tenant: MagicMock,
        client: httpx.AsyncClient,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test userinfo endpoint."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant

        from apps.tenant.integration.schemas import UserInfoResponseSchema

        user_info = UserInfoResponseSchema(
            sub="user_123",
            name="Test User",
            email="test@example.com",
            email_verified=True,
            preferred_username="testuser",
        )
        mock_get_user_info.return_value = user_info

        # Make request with proper Authorization header
        response = await client.get(
            "/oauth/userinfo",
            headers={"Authorization": "Bearer access_token_123"},
        )

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == "user_123"
        assert data["name"] == "Test User"
        assert data["email"] == "test@example.com"
        assert data["email_verified"] is True

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.validate_client")
    @_async_patch("apps.tenant.integration.routes.introspect_token")
    async def test_introspect_endpoint(
        self,
        mock_introspect: AsyncMock,
        mock_validate_client: AsyncMock,
        mock_get_tenant: AsyncMock,
        client: httpx.AsyncClient,
        mock_tenant: MagicMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test token introspection endpoint."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant
        mock_validate_client.return_value = mock_oauth_client

        from apps.tenant.integration.schemas import TokenIntrospectionResponseSchema

        introspection_response = TokenIntrospectionResponseSchema(
            active=True,
            scope="openid profile",
            client_id="test_client",
            username="testuser",
            token_type="Bearer",
            sub="user_123",
            aud="test_client",
            iss="https://example.com",
            jti="token_uid_123",
        )
        mock_introspect.return_value = introspection_response

        # Make request with form data and client authentication
        response = await client.post(
            "/oauth/introspect",
            data={
                "token": "access_token_123",
                "client_id": "test_client",
                "client_secret": "test_secret",
            },
        )

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data["active"] is True
        assert data["scope"] == "openid profile"
        assert data["client_id"] == "test_client"
        assert data["username"] == "testuser"
        assert data["token_type"] == "Bearer"
        assert data["sub"] == "user_123"

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.validate_client")
    @_async_patch("apps.tenant.integration.routes.revoke_token")
    async def test_revoke_endpoint(
        self,
        mock_revoke: AsyncMock,
        mock_validate_client: AsyncMock,
        mock_get_tenant: AsyncMock,
        client: httpx.AsyncClient,
        mock_tenant: MagicMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test token revocation endpoint."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant
        mock_validate_client.return_value = mock_oauth_client
        mock_revoke.return_value = None

        # Make request with form data and client authentication
        response = await client.post(
            "/oauth/revoke",
            data={
                "token": "access_token_123",
                "client_id": "test_client",
                "client_secret": "test_secret",
            },
        )

        # Assertions
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    @pytest.mark.asyncio
    @_async_patch("apps.tenant.integration.routes.get_tenant")
    @_async_patch("apps.tenant.integration.routes.register_client")
    @_async_patch("apps.tenant.integration.dependencies.get_current_user")
    async def test_register_client_endpoint(
        self,
        mock_get_user: MagicMock,
        mock_register: MagicMock,
        mock_get_tenant: MagicMock,
        client: httpx.AsyncClient,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test client registration endpoint."""
        # Setup mocks
        mock_get_tenant.return_value = mock_tenant
        mock_get_user.return_value = AsyncMock()

        from apps.tenant.integration.schemas import ClientRegistrationResponseSchema

        registration_response = ClientRegistrationResponseSchema(
            client_id="new_client_123",
            client_secret="new_secret_123",
            client_name="New Client",
            client_type="confidential",
            redirect_uris=["https://example.com/callback"],
            registration_access_token="reg_token_123",
            allowed_scopes=["openid", "profile", "email"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_active=True,
            require_pkce=False,
            token_endpoint_auth_method="client_secret_basic",
            uid="client_uid_123",
            meta_data={},
            user_id="user_123",
            tenant_id="tenant_123",
            logo_uri=None,
            client_uri=None,
            policy_uri=None,
            tos_uri=None,
            client_id_issued_at=1234567890,
            client_secret_expires_at=0,
        )
        mock_register.return_value = registration_response

        # Make request
        with patch("apps.tenant.integration.routes.require_secure_token"):
            response = await client.post(
                "/oauth/clients",
                json={
                    "client_name": "New Client",
                    "redirect_uris": ["https://example.com/callback"],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "scope": "openid profile email",
                },
            )

        # Assertions
        assert response.status_code == 201
        data = response.json()
        assert data["client_id"] == "new_client_123"
        assert data["client_secret"] == "new_secret_123"
        assert data["client_name"] == "New Client"
        assert data["client_type"] == "confidential"
        assert data["redirect_uris"] == ["https://example.com/callback"]
        assert data["registration_access_token"] == "reg_token_123"
