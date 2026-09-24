"""
OAuth2/OIDC schemas for tenant integration.

This module contains Pydantic schemas for OAuth2 and OpenID Connect
authorization server functionality.
"""

import ipaddress
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlparse

from fastapi_mongo_base.schemas import TenantUserEntitySchema
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from utils.validators import validate_external_https_url


class GrantType(StrEnum):
    """OAuth2 grant types (implicit grant is deprecated and not supported)."""

    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"


class OuathDeviceAuthorizationStatus(StrEnum):
    """Lifecycle status for an RFC 8628 device authorization request."""

    PENDING = "pending"
    AUTHORIZED = "authorized"
    DENIED = "denied"


class ResponseType(StrEnum):
    """Supported OAuth2 response types (authorization-code flow only)."""

    CODE = "code"


class TokenType(StrEnum):
    """OAuth2 Token Types."""

    BEARER = "Bearer"
    MAC = "MAC"


class Scope(StrEnum):
    """OAuth2 Scopes."""

    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"


class ClientType(StrEnum):
    """OAuth2 Client Types."""

    CONFIDENTIAL = "confidential"


def validate_redirect_uris(uris: list[str]) -> list[str]:
    """Require exact web redirects and permit plain HTTP only on loopback."""
    if not uris:
        raise ValueError("At least one redirect URI is required")
    for uri in uris:
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc or not parsed.hostname:
            raise ValueError(f"Invalid redirect URI: {uri}")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError(f"Invalid redirect URI: {uri}")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"Invalid scheme in redirect URI: {uri}")
        if parsed.scheme == "http":
            hostname = parsed.hostname.lower()
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = hostname == "localhost"
            if not is_loopback:
                raise ValueError("HTTP redirect URIs are allowed only on loopback")
    return uris


class OAuthClientSchema(TenantUserEntitySchema):
    """OAuth2 Client configuration schema."""

    client_id: str = Field(..., description="Unique client identifier")
    client_secret: str = Field(
        ..., description="Client secret (for confidential clients)"
    )
    client_name: str = Field(..., description="Human-readable client name")
    client_type: ClientType = Field(
        ..., description="Client type (public or confidential)"
    )

    # Redirect URIs
    redirect_uris: list[str] = Field(..., description="Allowed redirect URIs")

    # Scopes
    allowed_scopes: list[Scope] = Field(
        default=[Scope.OPENID, Scope.PROFILE, Scope.EMAIL],
        description="Allowed scopes for this client",
    )

    # Grant types
    grant_types: list[GrantType] = Field(
        default=[GrantType.AUTHORIZATION_CODE], description="Allowed grant types"
    )

    # Response types
    response_types: list[ResponseType] = Field(
        default=[ResponseType.CODE], description="Allowed response types"
    )

    # Client metadata
    logo_uri: str | None = Field(None, description="Client logo URI")
    client_uri: str | None = Field(None, description="Client homepage URI")
    policy_uri: str | None = Field(None, description="Client policy URI")
    tos_uri: str | None = Field(None, description="Terms of service URI")

    # Security
    require_pkce: bool = Field(
        True, description="Require PKCE for authorization code flow"
    )
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post"] = (
        Field(
            default="client_secret_basic",
            description="Token endpoint authentication method",
        )
    )

    @field_validator("require_pkce", mode="before")
    @classmethod
    def force_pkce(cls, _: object) -> bool:
        """PKCE S256 is mandatory, including for legacy stored clients."""
        return True

    # Status
    is_active: bool = Field(True, description="Whether the client is active")

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, v: list[str]) -> list[str]:
        """Validate redirect URIs."""
        return validate_redirect_uris(v)

    @field_validator("logo_uri", "client_uri", "policy_uri", "tos_uri")
    @classmethod
    def validate_metadata_uri(cls, value: str | None) -> str | None:
        """Prevent executable client metadata URLs from reaching consent UIs."""
        return validate_external_https_url(value)


class AuthorizationRequestSchema(BaseModel):
    """OAuth2 Authorization Request schema."""

    response_type: ResponseType = Field(..., description="Response type")
    client_id: str = Field(..., description="Client identifier")
    redirect_uri: str = Field(..., description="Redirect URI")
    scope: str | None = Field(None, description="Requested scopes (space-separated)")
    state: str | None = Field(None, description="State parameter for CSRF protection")

    # PKCE parameters
    code_challenge: str | None = Field(None, description="PKCE code challenge")
    code_challenge_method: str | None = Field(
        default="S256", description="PKCE code challenge method"
    )

    # OIDC parameters
    nonce: str | None = Field(None, description="Nonce for ID token")
    prompt: str | None = Field(None, description="Prompt parameter")
    max_age: int | None = Field(None, description="Maximum authentication age")

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str | None) -> list[str] | None:
        """Parse and validate scope string."""
        if not v:
            return None
        return [s.strip() for s in v.split() if s.strip()]


class TokenRequestSchema(BaseModel):
    """OAuth2 Token Request schema."""

    grant_type: GrantType = Field(..., description="Grant type")
    client_id: str | None = Field(..., description="Client identifier")
    client_secret: str | None = Field(None, description="Client secret")

    # Authorization Code Grant
    code: str | None = Field(None, description="Authorization code")
    redirect_uri: str | None = Field(None, description="Redirect URI")
    code_verifier: str | None = Field(None, description="PKCE code verifier")

    # Refresh Token Grant
    refresh_token: str | None = Field(None, description="Refresh token")

    # Client Credentials Grant
    scope: str | None = Field(None, description="Requested scopes")

    # Device Code Grant (RFC 8628)
    device_code: str | None = Field(None, description="Device code")

    @model_validator(mode="after")
    def validate_grant_specific_params(self) -> Self:
        """Validate grant-specific parameters."""
        if self.grant_type == GrantType.AUTHORIZATION_CODE:
            if not self.code:
                raise ValueError(
                    "Authorization code is required for authorization_code grant"
                )
            if not self.redirect_uri:
                raise ValueError(
                    "Redirect URI is required for authorization_code grant"
                )

        elif self.grant_type == GrantType.REFRESH_TOKEN:
            if not self.refresh_token:
                raise ValueError("Refresh token is required for refresh_token grant")

        elif self.grant_type == GrantType.CLIENT_CREDENTIALS:
            # Scope is optional; service accounts default to their stored scopes.
            pass

        elif self.grant_type == GrantType.DEVICE_CODE:
            if not self.device_code:
                raise ValueError("device_code is required for device_code grant")
            if not self.client_id:
                raise ValueError("client_id is required for device_code grant")

        return self


class OuathDeviceAuthorizationResponseSchema(BaseModel):
    """RFC 8628 device authorization response."""

    device_code: str = Field(..., description="Device code for token polling")
    user_code: str = Field(..., description="User-facing verification code")
    verification_uri: str = Field(..., description="URI where the user enters the code")
    verification_uri_complete: str = Field(
        ..., description="verification_uri with user_code prefilled"
    )
    expires_in: int = Field(..., description="Lifetime of the codes in seconds")
    interval: int = Field(..., description="Minimum polling interval in seconds")


class OuathDeviceAuthorizationInfoSchema(BaseModel):
    """Pending device authorization details for the consent UI."""

    user_code: str
    client_id: str
    client_name: str | None = None
    scope: list[str]
    expires_in: int


class OuathDeviceAuthorizationDecisionSchema(BaseModel):
    """Approve or deny a pending device authorization."""

    user_code: str = Field(..., min_length=1)
    approve: bool = True
    scope: list[str] | None = Field(
        None, description="Optional subset of requested scopes to grant"
    )


class TokenResponseSchema(BaseModel):
    """OAuth2 Token Response schema."""

    access_token: str = Field(..., description="Access token")
    token_type: TokenType = Field(default=TokenType.BEARER, description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: str | None = Field(None, description="Refresh token")
    scope: str | None = Field(None, description="Granted scopes")
    id_token: str | None = Field(None, description="ID token (OIDC)")


class TokenIntrospectionRequestSchema(BaseModel):
    """OAuth2 Token Introspection Request schema."""

    token: str = Field(..., description="Token to introspect")
    token_type_hint: str | None = Field(None, description="Hint about token type")


class TokenIntrospectionResponseSchema(BaseModel):
    """OAuth2 Token Introspection Response schema."""

    active: bool = Field(..., description="Whether the token is active")
    scope: str | None = Field(None, description="Token scopes")
    client_id: str | None = Field(None, description="Client ID")
    username: str | None = Field(None, description="Username")
    token_type: str | None = Field(None, description="Token type")
    exp: int | None = Field(None, description="Expiration time")
    iat: int | None = Field(None, description="Issued at time")
    nbf: int | None = Field(None, description="Not before time")
    sub: str | None = Field(None, description="Subject")
    aud: str | None = Field(None, description="Audience")
    iss: str | None = Field(None, description="Issuer")
    jti: str | None = Field(None, description="JWT ID")


class UserInfoResponseSchema(BaseModel):
    """OpenID Connect UserInfo Response schema."""

    sub: str = Field(..., description="Subject identifier")
    name: str | None = Field(None, description="Full name")
    given_name: str | None = Field(None, description="Given name")
    family_name: str | None = Field(None, description="Family name")
    middle_name: str | None = Field(None, description="Middle name")
    nickname: str | None = Field(None, description="Nickname")
    preferred_username: str | None = Field(None, description="Preferred username")
    profile: str | None = Field(None, description="Profile page URL")
    picture: str | None = Field(None, description="Profile picture URL")
    website: str | None = Field(None, description="Website URL")
    email: str | None = Field(None, description="Email address")
    email_verified: bool | None = Field(None, description="Email verification status")
    gender: str | None = Field(None, description="Gender")
    birthdate: str | None = Field(None, description="Birth date")
    zoneinfo: str | None = Field(None, description="Time zone")
    locale: str | None = Field(None, description="Locale")
    phone_number: str | None = Field(None, description="Phone number")
    phone_number_verified: bool | None = Field(
        None, description="Phone verification status"
    )
    address: dict[str, object] | None = Field(None, description="Address information")
    updated_at: int | None = Field(None, description="Last updated timestamp")


class ClientRegistrationRequestSchema(BaseModel):
    """Dynamic Client Registration Request schema."""

    model_config = ConfigDict(extra="forbid")

    client_name: str = Field(
        ..., min_length=1, max_length=200, description="Human-readable client name"
    )
    redirect_uris: list[str] = Field(..., description="Redirect URIs")
    grant_types: list[GrantType] = Field(
        default=[GrantType.AUTHORIZATION_CODE], description="Grant types"
    )
    response_types: list[ResponseType] = Field(
        default=[ResponseType.CODE], description="Response types"
    )
    scope: str = Field(default="openid profile email", description="Requested scopes")
    logo_uri: str | None = Field(None, description="Logo URI")
    client_uri: str | None = Field(None, description="Client URI")
    policy_uri: str | None = Field(None, description="Policy URI")
    tos_uri: str | None = Field(None, description="Terms of service URI")
    jwks_uri: str | None = Field(None, description="JWKS URI")
    jwks: dict[str, object] | None = Field(None, description="JWKS")
    software_id: str | None = Field(None, description="Software ID")
    software_version: str | None = Field(None, description="Software version")

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, value: list[str]) -> list[str]:
        """Apply the same exact redirect policy used by stored clients."""
        return validate_redirect_uris(value)

    @field_validator("logo_uri", "client_uri", "policy_uri", "tos_uri", "jwks_uri")
    @classmethod
    def validate_metadata_uri(cls, value: str | None) -> str | None:
        """Allow only non-credentialed HTTPS client metadata URLs."""
        return validate_external_https_url(value)


class ClientRegistrationResponseSchema(OAuthClientSchema):
    """Dynamic Client Registration Response schema."""

    client_id_issued_at: int = Field(..., description="Client ID issuance timestamp")
    client_secret_expires_at: int = Field(
        default=0, description="Client secret expiration"
    )
    registration_access_token: str = Field(..., description="Registration access token")


class ClientUpdateSchema(BaseModel):
    """Schema for updating OAuth client (partial update)."""

    model_config = ConfigDict(extra="forbid")

    client_name: str | None = Field(None, description="Human-readable client name")
    redirect_uris: list[str] | None = Field(None, description="Allowed redirect URIs")
    allowed_scopes: list[Scope] | None = Field(
        None, description="Allowed scopes for this client"
    )
    grant_types: list[GrantType] | None = Field(None, description="Allowed grant types")
    response_types: list[ResponseType] | None = Field(
        None, description="Allowed response types"
    )
    logo_uri: str | None = Field(None, description="Client logo URI")
    client_uri: str | None = Field(None, description="Client homepage URI")
    policy_uri: str | None = Field(None, description="Client policy URI")
    tos_uri: str | None = Field(None, description="Terms of service URI")
    require_pkce: Literal[True] | None = Field(
        None, description="Require PKCE for authorization code flow"
    )
    token_endpoint_auth_method: (
        Literal["client_secret_basic", "client_secret_post"] | None
    ) = Field(None, description="Token endpoint authentication method")
    is_active: bool | None = Field(None, description="Whether the client is active")

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, v: list[str] | None) -> list[str] | None:
        """Validate redirect URIs."""
        if v is None:
            return None
        return validate_redirect_uris(v)

    @field_validator("logo_uri", "client_uri", "policy_uri", "tos_uri")
    @classmethod
    def validate_metadata_uri(cls, value: str | None) -> str | None:
        """Allow only non-credentialed HTTPS client metadata URLs."""
        return validate_external_https_url(value)
