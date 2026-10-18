"""
Tenant configuration schemas.

This module contains all configuration-related schemas for tenant management.
"""

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, Field, HttpUrl
from usso.config import HeaderConfig

from apps.identity.auth.enums import (
    PASSWORD_OR_OTP,
    AuthFlow,
    AuthIdentifier,
)

from .branding import BrandingModel
from .messaging.enums import TemplateType
from .messaging.templates import DEFAULT_TEMPLATE_SET, MessageTemplate


class AuthenticationConfig(BaseModel):
    """
    Authentication configuration for a tenant.

    Defines the login flow(s) and related policies.
    """

    login_flow: AuthFlow = Field(
        default=PASSWORD_OR_OTP,
        description="The login flow configuration for this tenant",
    )
    identifier_patterns: dict[AuthIdentifier, str] = Field(
        default_factory=lambda: {
            AuthIdentifier.EMAIL: r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$",
            AuthIdentifier.PHONE: r"^(?:\+98|0098|98)?9\d{9}$|^09\d{9}$",
            AuthIdentifier.USERNAME: r"^[a-zA-Z0-9_]{3,}$",
        },
        description="Regular expressions used by clients to detect identifier types",
    )

    # MFA Configuration
    mfa_timeout: int = 60 * 5  # 5 minutes

    # OTP Configuration
    otp_timeout: int = 60 * 5
    otp_length: int = 6

    # Magic Link Configuration
    magic_link_timeout: int = 60 * 15

    # Password Policy
    password_min_length: int = 8
    password_prevent_reuse: bool = False
    password_prevent_dictionary: bool = True
    password_require_special: bool = True
    password_require_numbers: bool = True
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True

    # Session Configuration
    # Session Configuration (optional)
    max_concurrent_sessions: int | None = Field(
        default=None, description="Maximum concurrent sessions per user"
    )
    session_inactivity_timeout: int | None = Field(
        default=None, description="Session inactivity timeout in seconds"
    )
    require_recent_authentication: bool = Field(
        default=False,
        description="Require recent authentication for sensitive actions",
    )


class TokenConfig(BaseModel):
    """
    Token configuration for timeout and rotation settings.

    Attributes:
        access_timeout: Access token timeout in seconds.
        refresh_timeout: Refresh token timeout in seconds.
        refresh_token_rotation: Whether to rotate refresh tokens.
        refresh_sliding_timeout: Sliding window timeout for refresh tokens.
        refresh_token_reuse_grace_period: Grace period for refresh token reuse.
        temporary_token_timeout: Temporary token timeout in seconds.
        secure_action_timeout: Secure action token timeout in seconds.
        secure_action_max_uses: Maximum uses for secure action token.
        secure_session_timeout: Secure session token timeout in seconds.

    """

    # Access Token
    access_timeout: int = 60 * 10  # 10 minutes

    # Refresh Token
    refresh_timeout: int = 60 * 60 * 24 * 30  # 30 days
    refresh_token_rotation: bool = True
    refresh_sliding_timeout: int = 60 * 60 * 24 * 7  # 7 days
    refresh_token_reuse_grace_period: int = 60 * 1  # 1 minutes

    # Temporary Token
    temporary_token_timeout: int = 60 * 10  # 1 minutes

    # Secure Action Token
    secure_action_timeout: int = 60 * 1  # 1 minutes
    secure_action_max_uses: int = 1

    # Secure Session Token
    secure_session_timeout: int = 10 * 60  # 10 minutes

    def get_timeout(
        self,
        typ: Literal[
            "access", "refresh", "temporary", "one_time", "secure", "session"
        ] = "access",
    ) -> int:
        """
        Get timeout value for a token type.

        Args:
            typ: Token type to get timeout for.

        Returns:
            Timeout value in seconds.

        """
        match typ:
            case "access":
                return self.access_timeout
            case "refresh":
                return self.refresh_sliding_timeout
            case "temporary":
                return self.temporary_token_timeout
            case "one_time":
                return self.secure_action_timeout
            case "secure":
                return self.secure_session_timeout
            case "session":
                return self.refresh_timeout
            case _:
                raise ValueError(f"Invalid token type: {typ}")


class OAuthProviderConfig(BaseModel):
    """
    Configuration for OAuth provider settings.

    Attributes:
        name: The name of the OAuth provider (e.g., 'google', 'github')
        client_id: The OAuth client ID provided by the OAuth provider
        client_secret: The OAuth client secret provided by the OAuth provider
        redirect_uri: The callback URL where the OAuth
                      provider will redirect after authentication
        scopes: List of OAuth scopes to request from the provider

    """

    name: str = Field(
        description="The name of the OAuth provider (e.g., 'google', 'github')"
    )
    client_id: str = Field(
        description="The OAuth client ID provided by the OAuth provider"
    )
    client_secret: str = Field(
        description="The OAuth client secret provided by the OAuth provider"
    )
    redirect_uri: str | None = Field(
        default=None,
        description="The callback URL where the OAuth provider "
        "will redirect after authentication",
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="List of OAuth scopes to request from the provider",
    )


class OIDCConfig(BaseModel):
    """
    OIDC (OpenID Connect) configuration.

    Attributes:
        enabled: Whether OIDC functionality is enabled.
        issuer_url: OIDC issuer URL.
        jwks_uri: OIDC JWKS URI for key discovery.

    """

    enabled: bool = Field(
        default=False, description="Whether OIDC functionality is enabled"
    )
    issuer_url: HttpUrl = Field(..., description="OIDC issuer URL")
    jwks_uri: HttpUrl = Field(..., description="OIDC JWKS URI")


class APIKeyConfig(BaseModel):
    """
    API key configuration.

    Attributes:
        enabled: Whether API key authentication is enabled.
        prefix: Prefix for generated API keys.
        length: Length of generated API keys.

    """

    enabled: bool = Field(
        default=True, description="Whether API key authentication is enabled"
    )
    prefix: str = Field(default="uss_", description="Prefix for generated API keys")
    length: int = Field(default=32, description="Length of generated API keys")
    self_service_scopes: list[str] = Field(
        default_factory=list,
        description=(
            "Scopes any user may grant to an API key bound to themselves, on top "
            "of their role scopes (e.g. create:ai/ai-toolkit/*). Keep these "
            "below admin; on-behalf and management scopes stay role-only."
        ),
    )


class ServiceAccountConfig(BaseModel):
    """
    Service account configuration.

    Attributes:
        enabled: Whether service account authentication is enabled.
        prefix: Prefix for generated service account IDs.

    """

    enabled: bool = Field(
        default=True,
        description="Whether service account authentication is enabled",
    )
    prefix: str = Field(
        default="svc_", description="Prefix for generated service account IDs"
    )


class WebhookConfig(BaseModel):
    """
    Webhook configuration.

    Attributes:
        url: Webhook endpoint URL.
        headers: Optional HTTP headers for webhook requests.
        events: List of events that trigger this webhook.

    """

    url: HttpUrl = Field(..., description="The webhook endpoint URL")
    headers: dict[str, str] | None = Field(
        default=None,
        description="Optional HTTP headers to include in webhook requests",
    )
    events: list[str] = Field(
        default=[
            "user.created",
            "user.updated",
            "user.deleted",
            "referral.used",
            "referral_registered",
            "user.activated",
        ],
        description=(
            "Events that trigger this webhook "
            "(e.g. user.created, referral_registered for invite rewards)"
        ),
    )


class IntegrationConfig(BaseModel):
    """
    Integration configuration for OAuth, OIDC, API keys, and webhooks.

    Attributes:
        oauth_providers: Dictionary of OAuth2 provider configurations.
        oidc: Optional OIDC configuration.
        api_key: API key configuration.
        service_account: Service account configuration.
        webhooks: List of webhook configurations.

    """

    oauth_providers: dict[str, OAuthProviderConfig] = Field(
        default_factory=dict,
        description="Dictionary of OAuth2 provider configurations, "
        "keyed by provider name",
    )

    oidc: OIDCConfig | None = Field(default=None)

    api_key: APIKeyConfig = Field(default_factory=APIKeyConfig)

    service_account: ServiceAccountConfig = Field(default_factory=ServiceAccountConfig)

    webhooks: list[WebhookConfig] = Field(
        default_factory=list,
        description="List of webhook configurations for this tenant",
    )


class ApprovalMode(StrEnum):
    """Approval mode for new registrations."""

    NONE = "none"  # Free registration and immediate activation
    IDENTIFIER = "identifier"  # Email verification required
    MANUAL_REVIEW = "manual_review"  # Admin approval required
    ADDITIONAL = "additional"  # Additional verification (KYC, etc.)


class RegistrationConfig(BaseModel):
    """
    User registration configuration.

    Attributes:
        is_allowed: Whether user registration is allowed.
        approval_mode: Approval mode for new registrations.

    """

    is_allowed: bool = True
    approval_mode: ApprovalMode = ApprovalMode.IDENTIFIER
    allow_self_deactivate: bool = False
    invite_only: bool = Field(
        default=False,
        description=(
            "When true, registration requires a valid referral_code "
            "(bare code or invite link with ?ref=/referral_code= or /invite/{code})."
        ),
    )


class TenantJWTHeaderConfig(HeaderConfig):
    """Header configuration for tenant."""

    cookie_name: str
    header_name: str

    @classmethod
    def create_jwt_header_config(
        cls, token_type: Literal["access", "refresh", "temporary"]
    ) -> Self:
        """Create JWT header configuration."""
        cookie_name = f"usso-{token_type}-token"
        header_name = (
            "Authorization" if token_type == "access" else f"x-usso-{token_type}-token"
        )
        return cls(cookie_name=cookie_name, header_name=header_name)


class WorkspaceConfig(BaseModel):
    """
    Workspace configuration.

    Attributes:
        enabled: Whether workspace functionality is enabled.
        user_search_enabled: Whether users may be discovered by identifier
            prefix for workspace invitations.
        personal_workspace_active_by_default: Whether personal workspaces
            (uid == user.uid) are created as active. Projects that require
            external verification (e.g. ICE) should set this false.
        allow_member_create: Whether non-admin users may POST /workspaces
            (self-service org/child create). When false, only unscoped
            workspace admins (``admin:sso/usso/workspace`` / ``*:*``) may create.
        verification_provider: Optional plugin name for workspace create.
            When set (e.g. a registered verifier name), the plugin both resolves the org
            workspace (company-details inquiry) and verifies the caller
            (CEO registry). ``None`` means local find/create only.

    """

    enabled: bool = Field(default=True, description="Whether workspace is enabled")
    user_search_enabled: bool = Field(
        default=False,
        description=(
            "Whether searchable users can be found by identifier prefix "
            "for workspace invitations"
        ),
    )
    personal_workspace_active_by_default: bool = Field(
        default=True,
        description=(
            "Whether newly created personal workspaces start as active. "
            "Disable when workspace activation requires verification."
        ),
    )
    allow_member_create: bool = Field(
        default=True,
        description=(
            "Whether non-admin users may create workspaces via POST. "
            "Disable for invite/admin-provisioned tenants (e.g. CDS)."
        ),
    )
    verification_provider: str | None = Field(
        default=None,
        description=(
            "Optional workspace-create verifier plugin "
            "(plugin name registered at startup). "
            "None means local create without external registry calls."
        ),
    )


class AgentConfig(BaseModel):
    """
    Agent configuration.

    Attributes:
        enabled: Whether agents are enabled for this tenant.

    """

    enabled: bool = Field(
        default=False, description="Whether agents are enabled for this tenant"
    )


class TenantFrontendURLConfig(BaseModel):
    """
    Frontend URL configuration for tenant.

    Attributes:
        login_url: Login page URL path.
        register_url: Registration page URL path.
        reset_password_url: Password reset page URL path.
        verify_email_url: Email verification page URL path.
        verify_phone_url: Phone verification page URL path.

    """

    login_url: str = "/login"
    register_url: str = "/register"
    reset_password_url: str = "/reset-password"
    request_otp_url: str = "/request-otp"
    verify_email_url: str = "/verify-email"
    verify_phone_url: str = "/verify-phone"
    verify_national_id_url: str = "/verify-national-id"
    verify_id_url: str = "/verify-id"
    magic_link_url: str = "/magic-link"
    passkey_url: str = "/passkey"
    qr_url: str = "/qr"

    oauth_authorize_url: str = "/oauth/authorize"
    oauth_failed_url: str = "/oauth/failed"
    oauth_device_url: str = "/device"
    consent_url: str = "/oauth/consent"


class TenantCookieHeaderConfig(BaseModel):
    """Tenant cookie header configuration."""

    header_or_cookie: Literal["header", "cookie"] = Field(
        default="cookie",
        description="Whether to use headers or cookies for authentication",
    )
    cookie_domain: Literal["parent", "same-site"] = Field(
        default="same-site",
        description=(
            "Whether to use the parent domain or the same-site domain for the cookie"
        ),
    )
    is_http_only: bool = Field(
        default=True, description="Whether to use HTTP only for the cookie"
    )
    is_secure: bool = Field(
        default=True, description="Whether to use secure for the cookie"
    )


class TenantConfig(BaseModel):
    """Tenant configuration."""

    branding: BrandingModel = Field(default_factory=BrandingModel)
    default_redirect_url: str = "/"

    allowed_return_domains: list[str] = Field(
        default_factory=list,
        description="List of allowed return domains",
    )
    cookie_header_config: TenantCookieHeaderConfig = Field(
        default_factory=TenantCookieHeaderConfig,
        description="List of cookie headers for authentication",
    )

    # Authentication and Security
    auth: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    token: TokenConfig = Field(default_factory=TokenConfig)
    integration: IntegrationConfig = Field(default_factory=IntegrationConfig)

    image_captcha_tries: int = Field(
        default=2, description="Number of image captcha tries"
    )

    # Workspace Configuration
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)

    # Agent Configuration
    agents: AgentConfig = Field(default_factory=AgentConfig)

    # Email Configuration
    templates: dict[TemplateType, MessageTemplate] = Field(default=DEFAULT_TEMPLATE_SET)

    # Registration
    registration: RegistrationConfig = Field(default_factory=RegistrationConfig)


class PublicTenantConfig(BaseModel):
    """Public tenant configuration."""

    name: str | None = Field(default=None, description="Tenant name")
    branding: BrandingModel = Field(default_factory=BrandingModel)
    default_redirect_url: str = "/"
    auth: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    integration: list[str] = Field(
        default_factory=list,
        description="List of OAuth2 provider names",
    )
    telegram_client_id: str | None = Field(
        default=None,
        description="Telegram OIDC client_id for Login JS SDK, if configured",
    )

    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    registration: RegistrationConfig = Field(default_factory=RegistrationConfig)
