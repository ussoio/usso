"""Tests for OAuth2/OIDC services."""

from collections.abc import Generator
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.tenant.integration.schemas import (
    AuthorizationRequestSchema,
    ClientRegistrationRequestSchema,
    GrantType,
    ResponseType,
    Scope,
)
from apps.tenant.integration.services import (
    create_authorization_code,
    create_tokens,
    exchange_authorization_code,
    get_user_info,
    introspect_token,
    refresh_access_token,
    register_client,
    revoke_token,
    validate_authorization_request,
    validate_client,
)


class TestOAuthServices:
    """Test OAuth2/OIDC services."""

    @pytest.fixture
    def mock_tenant(self) -> AsyncMock:
        """Mock tenant."""
        tenant = AsyncMock()
        tenant.uid = "tenant_123"
        tenant.primary_url = "https://example.com"
        tenant.user_id = "user_123"
        tenant.config = SimpleNamespace(
            token=SimpleNamespace(access_timeout=3600, refresh_timeout=2_592_000)
        )
        tenant.sign_jwt = AsyncMock(return_value="signed_jwt_token")
        return tenant

    @pytest.fixture
    def mock_oauth_client(self) -> AsyncMock:
        """Mock OAuth client."""
        client = AsyncMock()
        client.client_id = "test_client"
        client.client_secret = "test_secret"
        client.client_name = "Test Client"
        client.client_type = "confidential"
        client.redirect_uris = ["https://example.com/callback"]
        client.allowed_scopes = [Scope.OPENID, Scope.PROFILE, Scope.EMAIL]
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

    @pytest.fixture
    def mock_authorization_code(self) -> AsyncMock:
        """Mock authorization code."""
        auth_code = AsyncMock()
        auth_code.code = "auth_code_123"
        auth_code.uid = "auth-code-uid"
        auth_code.client_id = "test_client"
        auth_code.user_id = "user_123"
        auth_code.tenant_id = "tenant_123"
        auth_code.redirect_uri = "https://example.com/callback"
        auth_code.scope = ["openid"]
        auth_code.nonce = None
        auth_code.code_challenge = None
        auth_code.code_challenge_method = None
        auth_code.expires_at = datetime.now(timezone.tz) + timedelta(minutes=10)
        auth_code.is_used = False
        auth_code.save = AsyncMock()
        return auth_code

    @pytest.fixture
    def mock_oauth_token(self) -> AsyncMock:
        """Mock OAuth token."""
        token = AsyncMock()
        token.token = "access_token_123"
        token.refresh_token = "refresh_token_123"
        token.token_type = AsyncMock()
        token.token_type.value = "Bearer"
        token.scope = ["openid"]
        token.client_id = "test_client"
        token.user_id = "user_123"
        token.tenant_id = "tenant_123"
        token.uid = "token_uid_123"  # Add uid for jti
        token.expires_at = datetime.now(timezone.tz) + timedelta(minutes=10)
        token.is_revoked = False
        token.save = AsyncMock()
        token.revoke_related_tokens = AsyncMock()
        return token

    @patch("apps.tenant.integration.services.get_oauth_client")
    async def test_validate_client_success(
        self,
        mock_get_client: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test successful client validation."""
        mock_get_client.return_value = mock_oauth_client

        result = await validate_client(
            "test_client", mock_tenant, "https://example.com/callback"
        )

        assert result == mock_oauth_client
        mock_get_client.assert_called_once_with(mock_tenant, "test_client")

    @patch("apps.tenant.integration.services.get_oauth_client")
    async def test_validate_client_not_found(
        self,
        mock_get_client: MagicMock,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test client validation when client not found."""
        mock_get_client.return_value = None

        with pytest.raises(Exception):  # Should raise HTTPException  # ruff:ignore[assert-raises-exception]
            await validate_client("invalid_client", mock_tenant)

    @patch("apps.tenant.integration.services.get_oauth_client")
    async def test_validate_client_inactive(
        self,
        mock_get_client: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test client validation when client is inactive."""
        mock_oauth_client.is_active = False
        mock_get_client.return_value = mock_oauth_client

        with pytest.raises(Exception):  # Should raise HTTPException  # ruff:ignore[assert-raises-exception]
            await validate_client("test_client", mock_tenant)

    @patch("apps.tenant.integration.services.validate_client")
    async def test_validate_authorization_request_success(
        self,
        mock_validate_client: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test successful authorization request validation."""
        mock_validate_client.return_value = mock_oauth_client

        request = AuthorizationRequestSchema(
            response_type=ResponseType.CODE,
            client_id="test_client",
            redirect_uri="https://example.com/callback",
            scope="openid profile",
            code_challenge="A" * 43,
            code_challenge_method="S256",
        )

        client, scopes = await validate_authorization_request(request, mock_tenant)

        assert client == mock_oauth_client
        assert "openid" in scopes
        assert "profile" in scopes

    @patch("apps.tenant.integration.services.validate_client")
    async def test_validate_authorization_request_invalid_response_type(
        self,
        mock_validate_client: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test authorization request validation with invalid response type."""
        mock_oauth_client.response_types = []
        mock_validate_client.return_value = mock_oauth_client

        request = AuthorizationRequestSchema(
            # Requesting code but client supports no response type
            response_type=ResponseType.CODE,
            client_id="test_client",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(Exception):  # Should raise HTTPException  # ruff:ignore[assert-raises-exception]
            await validate_authorization_request(request, mock_tenant)

    @patch("apps.tenant.integration.services.AuthorizationCode.find")
    @patch("apps.tenant.integration.services.AuthorizationCode.create_code")
    async def test_create_authorization_code(
        self,
        mock_create_code: AsyncMock,
        mock_find: AsyncMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
        mock_authorization_code: AsyncMock,
    ) -> None:
        """Test authorization code creation."""
        # Setup mocks
        mock_find.return_value.to_list = AsyncMock(return_value=[])  # No existing codes
        mock_create_code.return_value = mock_authorization_code

        result = await create_authorization_code(
            client=mock_oauth_client,
            user=mock_user,
            tenant=mock_tenant,
            redirect_uri="https://example.com/callback",
            scope=["openid"],
        )

        assert result == mock_authorization_code
        mock_authorization_code.save.assert_called_once()

    @patch("apps.tenant.integration.services.AuthorizationCode.get_by_code")
    @patch("apps.tenant.integration.services.User.get_item")
    async def test_exchange_authorization_code_success(
        self,
        mock_get_user: AsyncMock,
        mock_get_code: AsyncMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
        mock_authorization_code: AsyncMock,
    ) -> None:
        """Test successful authorization code exchange."""
        mock_get_code.return_value = mock_authorization_code
        mock_get_user.return_value = mock_user

        user, scope, nonce = await exchange_authorization_code(
            code="auth_code_123",
            client=mock_oauth_client,
            tenant=mock_tenant,
            redirect_uri="https://example.com/callback",
        )

        assert user == mock_user
        assert scope == ["openid"]
        assert nonce is None  # No nonce in this test case
        assert mock_authorization_code.is_used is True

    @patch("apps.tenant.integration.services.AuthorizationCode.get_by_code")
    async def test_exchange_authorization_code_invalid_code(
        self,
        mock_get_code: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test authorization code exchange with invalid code."""
        mock_get_code.return_value = None

        with pytest.raises(Exception):  # Should raise HTTPException  # ruff:ignore[assert-raises-exception]
            await exchange_authorization_code(
                code="invalid_code",
                client=mock_oauth_client,
                tenant=mock_tenant,
                redirect_uri="https://example.com/callback",
            )

    @patch("apps.tenant.integration.services.OAuthToken.find")
    @patch("apps.tenant.integration.services.OAuthToken.create_access_token")
    @patch("apps.tenant.integration.services.OAuthToken.create_refresh_token")
    @patch("apps.tenant.integration.services.create_id_token")
    async def test_create_tokens_success(
        self,
        mock_create_id_token: AsyncMock,
        mock_create_refresh: AsyncMock,
        mock_create_access: AsyncMock,
        mock_find: AsyncMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test successful token creation."""
        # Setup mocks
        mock_find.return_value.to_list = AsyncMock(
            return_value=[]
        )  # No existing tokens
        mock_create_access.return_value = mock_oauth_token
        mock_create_refresh.return_value = mock_oauth_token
        mock_oauth_token.raw_token = "access_token_123"
        mock_create_refresh.return_value = AsyncMock(
            raw_token="refresh_token_123",
            refresh_token="refresh-token-digest",
            save=AsyncMock(),
        )
        mock_create_id_token.return_value = "id_token_123"

        result = await create_tokens(
            client=mock_oauth_client,
            user=mock_user,
            tenant=mock_tenant,
            scope=["openid"],
        )

        assert result.access_token == "access_token_123"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.refresh_token == "refresh_token_123"
        assert result.scope == "openid"
        assert result.id_token == "id_token_123"

    @patch("apps.tenant.integration.services.OAuthToken.get_by_refresh_token")
    @patch("apps.tenant.integration.services.User.get_item")
    @patch("apps.tenant.integration.services.create_tokens")
    async def test_refresh_access_token_success(
        self,
        mock_create_tokens: AsyncMock,
        mock_get_user: AsyncMock,
        mock_get_token: AsyncMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test successful access token refresh."""
        mock_get_token.return_value = mock_oauth_token
        mock_get_user.return_value = mock_user

        token_response = AsyncMock()
        token_response.access_token = "new_access_token_123"
        token_response.token_type = "Bearer"
        token_response.expires_in = 3600
        token_response.refresh_token = "new_refresh_token_123"
        token_response.scope = "openid"
        mock_create_tokens.return_value = token_response

        collection = MagicMock(
            update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1))
        )
        with patch(
            "apps.tenant.integration.services.OAuthToken.get_pymongo_collection",
            return_value=collection,
        ):
            result = await refresh_access_token(
                refresh_token="refresh_token_123",
                client=mock_oauth_client,
                tenant=mock_tenant,
            )

        assert result == token_response
        mock_oauth_token.revoke_related_tokens.assert_called_once()

    @patch("apps.tenant.integration.services.OAuthToken.get_by_token")
    @patch("apps.tenant.integration.services.User.get_item")
    async def test_introspect_token_active(
        self,
        mock_get_user: MagicMock,
        mock_get_token: MagicMock,
        mock_tenant: AsyncMock,
        mock_user: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test token introspection for active token."""
        mock_get_token.return_value = mock_oauth_token
        mock_get_user.return_value = mock_user

        result = await introspect_token("access_token_123", mock_tenant)

        assert result.active is True
        assert result.scope == "openid"
        assert result.client_id == "test_client"
        assert result.username == "testuser"
        assert result.token_type == "Bearer"
        assert result.sub == "user_123"

    @patch("apps.tenant.integration.services.OAuthToken.get_by_token")
    async def test_introspect_token_inactive(
        self, mock_get_token: MagicMock, mock_tenant: AsyncMock
    ) -> None:
        """Test token introspection for inactive token."""
        mock_get_token.return_value = None

        result = await introspect_token("invalid_token", mock_tenant)

        assert result.active is False

    @patch("apps.tenant.integration.services.OAuthToken.get_by_token")
    @patch("apps.tenant.integration.services.User.get_item")
    async def test_get_user_info_success(
        self,
        mock_get_user: MagicMock,
        mock_get_token: MagicMock,
        mock_tenant: AsyncMock,
        mock_user: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test successful user info retrieval."""
        mock_get_token.return_value = mock_oauth_token
        mock_get_user.return_value = mock_user

        result = await get_user_info("access_token_123", mock_tenant)

        assert result.sub == "user_123"
        assert result.name == "Test User"
        assert result.preferred_username == "testuser"

    @patch("apps.tenant.integration.services.OAuthToken.get_by_token")
    async def test_get_user_info_invalid_token(
        self,
        mock_get_token: MagicMock,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test user info retrieval with invalid token."""
        mock_get_token.return_value = None

        with pytest.raises(Exception):  # Should raise HTTPException  # ruff:ignore[assert-raises-exception]
            await get_user_info("invalid_token", mock_tenant)

    @patch("apps.tenant.integration.services.OAuthClient")
    async def test_register_client_success(
        self,
        mock_oauth_client_class: MagicMock,
        mock_tenant: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test successful client registration."""
        # Setup mocks
        mock_client = AsyncMock()
        mock_client.client_id = "new_client_123"
        mock_client.client_secret = "new_secret_123"
        mock_client.client_name = "New Client"
        mock_client.client_type = "confidential"
        mock_client.redirect_uris = ["https://example.com/callback"]
        mock_client.allowed_scopes = [Scope.OPENID, Scope.PROFILE, Scope.EMAIL]
        mock_client.grant_types = [GrantType.AUTHORIZATION_CODE]
        mock_client.response_types = [ResponseType.CODE]
        mock_client.logo_uri = None
        mock_client.client_uri = None
        mock_client.policy_uri = None
        mock_client.tos_uri = None
        mock_client.require_pkce = True
        mock_client.token_endpoint_auth_method = "client_secret_basic"
        mock_client.is_active = True
        mock_client.save = AsyncMock()
        mock_client.model_dump = lambda **_kwargs: {
            "client_id": "new_client_123",
            "client_name": "New Client",
            "client_type": "confidential",
            "redirect_uris": ["https://example.com/callback"],
            "allowed_scopes": [Scope.OPENID, Scope.PROFILE, Scope.EMAIL],
            "grant_types": [GrantType.AUTHORIZATION_CODE],
            "response_types": [ResponseType.CODE],
            "logo_uri": None,
            "client_uri": None,
            "policy_uri": None,
            "tos_uri": None,
            "require_pkce": True,
            "token_endpoint_auth_method": "client_secret_basic",
            "is_active": True,
            "user_id": "user_123",
            "tenant_id": "tenant_123",
        }

        mock_oauth_client_class.generate_client_id.return_value = "new_client_123"
        mock_oauth_client_class.generate_client_secret.return_value = "new_secret_123"
        mock_oauth_client_class.return_value = mock_client

        request = ClientRegistrationRequestSchema(
            client_name="New Client",
            redirect_uris=["https://example.com/callback"],
            grant_types=[GrantType.AUTHORIZATION_CODE],
            response_types=[ResponseType.CODE],
            scope="openid profile email",
        )

        result = await register_client(request, mock_tenant, mock_user)

        assert result.client_id == "new_client_123"
        assert result.client_secret == "new_secret_123"
        assert result.client_name == "New Client"
        assert result.client_type == "confidential"
        assert result.redirect_uris == ["https://example.com/callback"]
        assert result.registration_access_token is not None

    @patch("apps.tenant.integration.services.OAuthToken.get_by_token")
    async def test_revoke_token_success(
        self,
        mock_get_token: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test successful token revocation."""
        mock_get_token.return_value = mock_oauth_token

        await revoke_token("access_token_123", mock_oauth_client, mock_tenant)

        mock_oauth_token.revoke_related_tokens.assert_called_once()

    @patch("apps.tenant.integration.services.OAuthToken.get_by_token")
    async def test_revoke_token_not_found(
        self,
        mock_get_token: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
    ) -> None:
        """Test token revocation when token not found."""
        mock_get_token.return_value = None

        # Should not raise an exception
        await revoke_token("invalid_token", mock_oauth_client, mock_tenant)

    # Nonce handling tests
    @patch("apps.tenant.integration.services.AuthorizationCode.get_by_code")
    @patch("apps.tenant.integration.services.User.get_item")
    async def test_exchange_authorization_code_with_nonce(
        self,
        mock_get_user: MagicMock,
        mock_get_code: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test exchange authorization code returns nonce when present."""
        # Setup mock authorization code with nonce
        mock_auth_code = AsyncMock()
        mock_auth_code.uid = "auth-code-uid"
        mock_auth_code.client_id = "test_client"
        mock_auth_code.redirect_uri = "https://example.com/callback"
        mock_auth_code.is_used = False
        mock_auth_code.scope = ["openid", "profile"]
        mock_auth_code.nonce = "test_nonce_123"
        mock_auth_code.code_challenge = None  # No PKCE
        mock_auth_code.code_challenge_method = None
        mock_auth_code.save = AsyncMock()
        mock_get_code.return_value = mock_auth_code
        mock_get_user.return_value = mock_user

        user, scope, nonce = await exchange_authorization_code(
            code="auth_code_123",
            client=mock_oauth_client,
            tenant=mock_tenant,
            redirect_uri="https://example.com/callback",
        )

        assert user == mock_user
        assert scope == ["openid", "profile"]
        assert nonce == "test_nonce_123"

    @patch("apps.tenant.integration.services.AuthorizationCode.get_by_code")
    @patch("apps.tenant.integration.services.User.get_item")
    async def test_exchange_authorization_code_without_nonce(
        self,
        mock_get_user: MagicMock,
        mock_get_code: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test exchange authorization code returns None nonce when not present."""
        # Setup mock authorization code without nonce
        mock_auth_code = AsyncMock()
        mock_auth_code.uid = "auth-code-uid"
        mock_auth_code.client_id = "test_client"
        mock_auth_code.redirect_uri = "https://example.com/callback"
        mock_auth_code.is_used = False
        mock_auth_code.scope = ["openid", "profile"]
        mock_auth_code.nonce = None
        mock_auth_code.code_challenge = None  # No PKCE
        mock_auth_code.code_challenge_method = None
        mock_auth_code.save = AsyncMock()
        mock_get_code.return_value = mock_auth_code
        mock_get_user.return_value = mock_user

        user, scope, nonce = await exchange_authorization_code(
            code="auth_code_123",
            client=mock_oauth_client,
            tenant=mock_tenant,
            redirect_uri="https://example.com/callback",
        )

        assert user == mock_user
        assert scope == ["openid", "profile"]
        assert nonce is None

    @patch("apps.tenant.integration.services.OAuthToken.find")
    @patch("apps.tenant.integration.services.OAuthToken.create_access_token")
    @patch("apps.tenant.integration.services.OAuthToken.create_refresh_token")
    @patch("apps.tenant.integration.services.create_id_token")
    async def test_create_tokens_with_nonce(
        self,
        mock_create_id_token: AsyncMock,
        mock_create_refresh: AsyncMock,
        mock_create_access: AsyncMock,
        mock_find: AsyncMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test token creation with nonce parameter."""
        # Setup mocks
        mock_find.return_value.to_list = AsyncMock(return_value=[])
        mock_create_access.return_value = mock_oauth_token
        mock_create_refresh.return_value = mock_oauth_token
        mock_oauth_token.raw_token = "access_token_123"
        mock_create_refresh.return_value = AsyncMock(
            raw_token="refresh_token_123",
            refresh_token="refresh-token-digest",
            save=AsyncMock(),
        )
        mock_create_id_token.return_value = "id_token_with_nonce"

        result = await create_tokens(
            client=mock_oauth_client,
            user=mock_user,
            tenant=mock_tenant,
            scope=["openid"],
            nonce="test_nonce_123",
        )

        # Verify create_id_token was called with nonce
        mock_create_id_token.assert_called_once_with(
            user=mock_user,
            tenant=mock_tenant,
            client=mock_oauth_client,
            scope=["openid"],
            nonce="test_nonce_123",
        )

        assert result.id_token == "id_token_with_nonce"

    @patch("apps.tenant.integration.services.OAuthToken.find")
    @patch("apps.tenant.integration.services.OAuthToken.create_access_token")
    @patch("apps.tenant.integration.services.OAuthToken.create_refresh_token")
    @patch("apps.tenant.integration.services.create_id_token")
    async def test_create_tokens_without_nonce(
        self,
        mock_create_id_token: AsyncMock,
        mock_create_refresh: AsyncMock,
        mock_create_access: AsyncMock,
        mock_find: AsyncMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
        mock_oauth_token: AsyncMock,
    ) -> None:
        """Test token creation without nonce parameter."""
        # Setup mocks
        mock_find.return_value.to_list = AsyncMock(return_value=[])
        mock_create_access.return_value = mock_oauth_token
        mock_create_refresh.return_value = mock_oauth_token
        mock_oauth_token.raw_token = "access_token_123"
        mock_create_refresh.return_value = AsyncMock(
            raw_token="refresh_token_123",
            refresh_token="refresh-token-digest",
            save=AsyncMock(),
        )
        mock_create_id_token.return_value = "id_token_without_nonce"

        result = await create_tokens(
            client=mock_oauth_client,
            user=mock_user,
            tenant=mock_tenant,
            scope=["openid"],
            nonce=None,
        )

        # Verify create_id_token was called with None nonce
        mock_create_id_token.assert_called_once_with(
            user=mock_user,
            tenant=mock_tenant,
            client=mock_oauth_client,
            scope=["openid"],
            nonce=None,
        )

        assert result.id_token == "id_token_without_nonce"

    @patch("apps.tenant.integration.services.User.get_identifiers")
    async def test_create_id_token_with_nonce(
        self,
        mock_get_identifiers: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test ID token creation includes nonce in claims."""
        # Setup mock user identifiers
        mock_identifiers = [AsyncMock(type="email", identifier="test@example.com")]
        mock_get_identifiers.return_value = mock_identifiers

        # Mock tenant sign_jwt to capture the claims
        def mock_sign_jwt(claims: dict) -> str:
            # Verify nonce is in claims
            assert "nonce" in claims
            assert claims["nonce"] == "test_nonce_123"
            return "signed_jwt_with_nonce"

        mock_tenant.sign_jwt = mock_sign_jwt

        from apps.tenant.integration.services import create_id_token

        result = await create_id_token(
            user=mock_user,
            tenant=mock_tenant,
            client=mock_oauth_client,
            scope=["openid", "profile", "email"],
            nonce="test_nonce_123",
        )

        assert result == "signed_jwt_with_nonce"

    @patch("apps.tenant.integration.services.User.get_identifiers")
    async def test_create_id_token_without_nonce(
        self,
        mock_get_identifiers: MagicMock,
        mock_tenant: AsyncMock,
        mock_oauth_client: AsyncMock,
        mock_user: AsyncMock,
    ) -> None:
        """Test ID token creation without nonce in claims."""
        # Setup mock user identifiers
        mock_identifiers = [AsyncMock(type="email", identifier="test@example.com")]
        mock_get_identifiers.return_value = mock_identifiers

        # Mock tenant sign_jwt to capture the claims
        def mock_sign_jwt(claims: dict) -> str:
            # Verify nonce is not in claims when None
            assert "nonce" not in claims
            return "signed_jwt_without_nonce"

        mock_tenant.sign_jwt = mock_sign_jwt

        from apps.tenant.integration.services import create_id_token

        result = await create_id_token(
            user=mock_user,
            tenant=mock_tenant,
            client=mock_oauth_client,
            scope=["openid", "profile", "email"],
            nonce=None,
        )

        assert result == "signed_jwt_without_nonce"

    @pytest.fixture(autouse=True)
    def mock_authorization_code_collection(self) -> Generator[None]:
        """Make authorization-code consumption succeed atomically in unit tests."""
        collection = MagicMock()
        collection.update_one = AsyncMock(
            return_value=SimpleNamespace(modified_count=1)
        )
        with patch(
            "apps.tenant.integration.services.AuthorizationCode.get_pymongo_collection",
            return_value=collection,
        ):
            yield
