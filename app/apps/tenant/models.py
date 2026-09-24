"""
Tenant database models.

This module defines the Tenant model which represents an organization or
workspace in the multi-tenant SSO system, including JWT signing capabilities
and authentication configuration.
"""

import hashlib
from enum import Enum
from functools import partial
from typing import ClassVar, Self

from aiocache import cached
from fastapi_mongo_base.models import ASCENDING, IndexModel, UserOwnedEntity
from pydantic import Field
from usso.config import APIHeaderConfig, AuthConfig
from usso.integrations.fastapi import USSOAuthentication
from usso_jwt.algorithms import HMACKey
from usso_jwt.enums import Algorithm
from usso_jwt.utils import b64url_encode

from server.config import Settings

from .config import TenantJWTHeaderConfig
from .schemas import TenantRetrieveSchema, normalize_tenant_domains
from .secrets import TenantSecrets


class Tenant(TenantRetrieveSchema, UserOwnedEntity):
    """
    Tenant model representing an organization or workspace in the system.

    Each tenant has its own domains, configuration, secrets, and authentication
    settings. Provides JWT signing and authentication configuration methods.
    """

    secrets: TenantSecrets = Field(
        default_factory=TenantSecrets, description="Tenant secrets"
    )

    class Settings:
        """
        Tenant model database settings.

        Configures validation and database indexes.
        """

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *UserOwnedEntity.Settings.indexes,
            IndexModel([("name", ASCENDING)]),
            IndexModel([("domains", ASCENDING)], unique=True),
        ]

    @classmethod
    @cached(ttl=60 * 60)
    async def get_from_domain(cls, domain: str) -> Self | None:
        """
        Get tenant by domain with caching.

        Args:
            domain: Domain string to search for.

        Returns:
            Tenant instance if found, None otherwise.

        """
        try:
            normalized = normalize_tenant_domains([domain])[0]
        except ValueError:
            return None
        # Full-URL variants support reading legacy rows until they are re-saved.
        variants = [
            normalized,
            f"https://{normalized}",
            f"https://{normalized}/",
            f"http://{normalized}",
            f"http://{normalized}/",
        ]
        return await cls.find_one({"domains": {"$in": variants}})

    def sign_jwt(self, payload: dict, hmac: bool = False) -> str:
        """
        Sign a JWT payload with the tenant's latest key.

        Args:
            payload: JWT payload dictionary to sign.
            hmac: If True, use HMAC algorithm instead of the key's algorithm
                  with key derived from hash(private_key).

        Returns:
            Signed JWT token string.

        """
        from usso_jwt import sign

        key = self.secrets.keys[-1]  # latest key by creation date
        if hmac:
            alg = Algorithm.HS256
            sign_pass = hashlib.sha256(
                key.private_key + Settings.system_password.encode()
            ).digest()
            sign_key = HMACKey.load_jwk({
                "kty": "oct",
                "alg": "HS256",
                "k": b64url_encode(sign_pass),
            }).key
        else:
            alg = key.alg
            sign_key = key.get_key()

        headers = {
            "kid": key.kid,
            "typ": "JWT",
            "alg": alg,
        }
        payload["iss"] = payload.get("iss", self.primary_domain)
        return sign.generate_jwt(
            header=headers,
            payload=payload,
            key=sign_key,
            alg=alg,
            password=Settings.system_password,
        )

    def jwt_config(self, token_type: str) -> AuthConfig:
        """
        Get JWT authentication configuration for a token type.

        Args:
            token_type: Type of token (e.g., 'access', 'refresh', 'temporary').

        Returns:
            List of AuthConfig instances, one for each tenant domain.

        """

        def get_url(domain: str) -> str:
            if domain.startswith("http"):
                return domain
            if "localhost" in domain:
                return f"http://{domain}"
            return f"https://{domain}"

        from apps.identity.api_key.services import get_api_key_data

        return [
            AuthConfig(
                jwt_header=TenantJWTHeaderConfig.create_jwt_header_config(token_type),
                api_key_header=APIHeaderConfig(
                    type="CustomHeader",
                    name="x-api-key",
                    verify_endpoint=f"{get_url(domain)}/api/sso/v1/apikeys/verify",
                    api_key_verifier_async=partial(
                        get_api_key_data,
                        tenant_id=self.uid,
                    ),
                ),
                key=(
                    self.secrets.keys[-1].public_pem
                    if token_type not in ["temporary", "refresh", "secure"]
                    else hashlib.sha256(
                        self.secrets.keys[-1].private_key
                        + Settings.system_password.encode()
                    ).digest()
                    # else hashlib.sha256(self.secrets.keys[-1].private_key).digest()
                ),
                issuer=get_url(domain),
                type=(
                    self.secrets.keys[-1].alg
                    if token_type not in ["temporary", "refresh", "secure"]
                    else "HS256"
                ),
            )
            for domain in self.domains
        ]

    def get_auth(
        self, token_type: str, raise_exception: bool = True
    ) -> USSOAuthentication:
        """
        Get USSO authentication instance for a token type.

        Args:
            token_type: Type of token (e.g., 'access', 'refresh', 'temporary').
            raise_exception: Whether to raise exceptions on authentication failure.

        Returns:
            USSOAuthentication instance configured for this tenant.

        """
        if isinstance(token_type, Enum):
            token_type = token_type.value
        return USSOAuthentication(
            jwt_config=self.jwt_config(token_type),
            expected_token_type=token_type,
            raise_exception=raise_exception,
        )

    @property
    def access_auth(self) -> USSOAuthentication:
        """
        USSO authentication for access tokens.

        Returns:
            USSOAuthentication instance for access token validation.

        """
        return self.get_auth("access")

    @property
    def refresh_auth(self) -> USSOAuthentication:
        """
        USSO authentication for refresh tokens.

        Returns:
            USSOAuthentication instance for refresh token validation.

        """
        return self.get_auth("refresh")

    @property
    def temporary_auth(self) -> USSOAuthentication:
        """
        USSO authentication for temporary tokens.

        Returns:
            USSOAuthentication instance for temporary token validation
            (does not raise exceptions on failure).

        """
        return self.get_auth("temporary", raise_exception=False)

    @property
    def secure_auth(self) -> USSOAuthentication:
        """USSO authentication for secure session tokens (HMAC)."""
        return self.get_auth("secure", raise_exception=False)
