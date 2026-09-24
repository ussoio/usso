"""
Tenant secrets and sensitive data schemas.

This module contains schemas for handling sensitive tenant
data like keys and credentials.
"""

from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator
from usso_jwt.enums import Algorithm

from .keys import TenantKey
from .messaging.schemas import TenantChannelConfig


class OAuthSecret(BaseModel):
    """
    OAuth provider secret configuration.

    Attributes:
        discovery_url: OAuth discovery/well-known URL.
        client_id: OAuth client ID.
        client_secret: OAuth client secret.
        scopes: List of OAuth scopes to request.
        use_pkce: Whether to use PKCE (S256) on authorize/token.
        token_auth_method: How to authenticate at the token endpoint.

    """

    discovery_url: str = Field(
        default="",
        description="Discovery URL for the OAuth provider",
    )
    client_id: str = Field(..., description="Client ID for the OAuth provider")
    client_secret: str = Field(..., description="Client secret for the OAuth provider")
    scopes: list[str] = Field(
        default=["openid", "profile", "email"],
        description="Scopes for the OAuth provider",
    )
    use_pkce: bool = Field(
        default=False,
        description="Use PKCE (S256) for authorization code flow",
    )
    token_auth_method: Literal["client_secret_post", "client_secret_basic"] = Field(
        default="client_secret_post",
        description="Token endpoint client authentication method",
    )


class TrustedIdentityProvider(BaseModel):
    """
    Trusted identity provider configuration.

    Used for validating tokens from external identity providers
    (e.g., for magic links).

    Attributes:
        issuer: Issuer identifier.
        public_pem: Public key in PEM format for signature verification.
        jwks_url: Remote JWKS endpoint URL for key discovery.
        jwk: Inline JWK dictionary for signature verification.
        maximum_age: Maximum age of tokens in seconds.

    """

    issuer: str
    public_pem: str | None = None
    jwks_url: str | None = None
    jwk: dict | None = None
    maximum_age: int

    @model_validator(mode="after")
    def validate_key_source(self) -> Self:
        """Require exactly one verification source."""
        key_sources = [self.public_pem, self.jwks_url, self.jwk]
        if sum(source is not None for source in key_sources) != 1:
            raise ValueError(
                "Exactly one of public_pem, jwks_url, or jwk must be provided"
            )
        return self

    @property
    def key(self) -> str | dict | None:
        """Verification key material for JWTConfig(key=...)."""
        if self.public_pem is not None:
            return self.public_pem
        return self.jwk


class TenantSecrets(BaseModel):
    """
    Tenant secrets and sensitive configuration.

    Contains all sensitive tenant data including cryptographic keys,
    OAuth secrets, messaging channel configs, and trusted identity providers.

    Attributes:
        keys: List of cryptographic keys for JWT signing.
        oauth_secrets: Dictionary of OAuth provider secrets
            (use key ``telegram`` for Telegram OIDC Login).
        channel_configs: Dictionary of messaging channel configurations.
        trusted_identity_providers: Dictionary of trusted external identity providers.
        third_party_validation_url: Optional URL for third-party token validation.

    """

    # Cryptographic Keys
    keys: list[TenantKey] = Field(
        default_factory=list,
        description="List of Signing Keys for the tenant",
    )
    # OAuth Secrets
    oauth_secrets: dict[str, OAuthSecret] = Field(
        default_factory=dict,
        description="OAuth secrets for the tenant",
    )

    # Message Channel Configurations
    channel_configs: dict[str, TenantChannelConfig] = Field(
        default_factory=dict,
        description=(
            "Messaging channel provider configs keyed by channel type "
            "(sms, email, bale, telegram, …)."
        ),
    )

    # use for magic links
    trusted_identity_providers: dict[str, TrustedIdentityProvider] = Field(
        default_factory=dict,
        description=(
            "External IdPs trusted for validating magic-link / federation JWTs, "
            "keyed by issuer."
        ),
    )

    # Vault Configuration / other 3rd party siging services
    third_party_validation_url: str | None = None

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_key_salts(cls, value: object) -> object:
        """Move the former tenant-wide salt into every legacy key."""
        if not isinstance(value, dict):
            return value

        data = dict(value)
        legacy_salt = data.pop("pass_salt", None)
        raw_keys = data.get("keys")
        if not isinstance(raw_keys, list):
            return data

        migrated_keys: list[object] = []
        for raw_key in raw_keys:
            if isinstance(raw_key, TenantKey):
                migrated_keys.append(raw_key)
                continue
            if not isinstance(raw_key, dict):
                migrated_keys.append(raw_key)
                continue
            key_data = dict(raw_key)
            if not key_data.get("pass_salt"):
                if not isinstance(legacy_salt, str) or not legacy_salt:
                    raise ValueError("Tenant key is missing its pass_salt")
                key_data["pass_salt"] = legacy_salt
            migrated_keys.append(key_data)
        data["keys"] = migrated_keys
        return data

    @model_validator(mode="after")
    def set_default_keys(self) -> Self:
        """Set default keys if none are provided."""
        if not self.keys:
            self.keys = [TenantKey.create_random_key()]
        return self

    @classmethod
    def generate_random_tenant_secrets(cls, alg: Algorithm = Algorithm.Ed25519) -> Self:
        """
        Generate random tenant secrets with a new key pair.

        Args:
            alg: Algorithm to use for key generation.

        Returns:
            New TenantSecrets instance with generated keys.

        """
        return cls(keys=[TenantKey.create_random_key(alg=alg)])
