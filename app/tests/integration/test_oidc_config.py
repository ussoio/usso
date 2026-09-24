"""Tests for OIDC configuration endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from apps.tenant.integration.oidc import router


class TestOIDCConfig:
    """Test OIDC configuration endpoints."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    @pytest.fixture
    def mock_tenant(self) -> AsyncMock:
        """Mock tenant."""
        tenant = AsyncMock()
        tenant.uid = "tenant_123"
        tenant.primary_url = "https://example.com"
        tenant.secrets = AsyncMock()
        tenant.secrets.keys = [
            AsyncMock(
                public_jwk={"kty": "RSA", "kid": "key1"},
                public_pem="-----BEGIN PUBLIC KEY-----\nkey1\n-----END PUBLIC KEY-----",
                is_active=True,
                use="sig",
            ),
            AsyncMock(
                public_jwk={"kty": "RSA", "kid": "key2"},
                public_pem="-----BEGIN PUBLIC KEY-----\nkey2\n-----END PUBLIC KEY-----",
                is_active=True,
                use="sig",
            ),
        ]
        return tenant

    @patch("apps.tenant.integration.oidc.get_tenant", new_callable=AsyncMock)
    def test_jwks_endpoint(
        self,
        mock_get_tenant: AsyncMock,
        client: TestClient,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test JWKS endpoint."""
        mock_get_tenant.return_value = mock_tenant

        response = client.get("/.well-known/jwks.json")

        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) == 2
        assert data["keys"][0]["kty"] == "RSA"
        assert data["keys"][0]["kid"] == "key1"
        assert data["keys"][1]["kty"] == "RSA"
        assert data["keys"][1]["kid"] == "key2"

    @patch("apps.tenant.integration.oidc.get_tenant", new_callable=AsyncMock)
    def test_openid_configuration_endpoint(
        self,
        mock_get_tenant: AsyncMock,
        client: TestClient,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test OpenID Connect configuration endpoint."""
        mock_get_tenant.return_value = mock_tenant

        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200
        data = response.json()

        # Check required OIDC configuration fields
        assert data["issuer"] == "https://example.com"
        assert (
            data["authorization_endpoint"]
            == "https://example.com/api/sso/v1/oauth/authorize"
        )
        assert data["token_endpoint"] == "https://example.com/api/sso/v1/oauth/token"
        assert (
            data["userinfo_endpoint"] == "https://example.com/api/sso/v1/oauth/userinfo"
        )
        assert data["jwks_uri"] == "https://example.com/.well-known/jwks.json"

        # Check supported response types
        assert "response_types_supported" in data
        assert data["response_types_supported"] == ["code"]
        assert "none" not in data["token_endpoint_auth_methods_supported"]

        # Check supported subject types
        assert data["subject_types_supported"] == ["public"]

        # Check supported signing algorithms
        assert "id_token_signing_alg_values_supported" in data
        assert "RS256" in data["id_token_signing_alg_values_supported"]
        assert "ES256" in data["id_token_signing_alg_values_supported"]
        assert "EdDSA" in data["id_token_signing_alg_values_supported"]

        # Check supported scopes
        assert "scopes_supported" in data
        assert "openid" in data["scopes_supported"]
        assert "profile" in data["scopes_supported"]
        assert "email" in data["scopes_supported"]

        # Check supported token endpoint auth methods
        assert "token_endpoint_auth_methods_supported" in data
        assert "client_secret_basic" in data["token_endpoint_auth_methods_supported"]
        assert "client_secret_post" in data["token_endpoint_auth_methods_supported"]

        # Check supported claims
        assert "claims_supported" in data
        assert "sub" in data["claims_supported"]
        assert "iss" in data["claims_supported"]
        assert "aud" in data["claims_supported"]
        assert "exp" in data["claims_supported"]
        assert "iat" in data["claims_supported"]
        assert "name" in data["claims_supported"]
        assert "email" in data["claims_supported"]

        # Check supported grant types
        assert "grant_types_supported" in data
        assert "authorization_code" in data["grant_types_supported"]
        assert "refresh_token" in data["grant_types_supported"]
        assert "client_credentials" in data["grant_types_supported"]

        # Check supported code challenge methods
        assert "code_challenge_methods_supported" in data
        assert "S256" in data["code_challenge_methods_supported"]
        assert "plain" not in data["code_challenge_methods_supported"]

    @patch("apps.tenant.integration.oidc.get_tenant", new_callable=AsyncMock)
    def test_jwks_pem_endpoint(
        self,
        mock_get_tenant: AsyncMock,
        client: TestClient,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test JWKS PEM endpoint."""
        mock_get_tenant.return_value = mock_tenant

        response = client.get("/.well-known/public-keys.pem")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-pem-file")
        assert "-----BEGIN PUBLIC KEY-----" in response.text
        assert "key1" in response.text
        assert "key2" in response.text

    @patch("apps.tenant.integration.oidc.get_tenant", new_callable=AsyncMock)
    def test_jwks_endpoint_with_domain(
        self,
        mock_get_tenant: AsyncMock,
        client: TestClient,
        mock_tenant: AsyncMock,
    ) -> None:
        """Test JWKS endpoint with domain parameter."""
        mock_get_tenant.return_value = mock_tenant

        response = client.get("/.well-known/jwks.json?domain=test.example.com")

        assert response.status_code == 200
        mock_get_tenant.assert_called_once()
        # Check that domain parameter was passed
        call_args = mock_get_tenant.call_args
        assert call_args[1]["domain"] == "test.example.com"
