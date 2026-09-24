"""
Tenant Pydantic schemas.

This module defines Pydantic models for tenant creation, updates, and retrieval,
including validation rules and field descriptions.
"""

from typing import Any
from urllib.parse import urlsplit

from fastapi_mongo_base.schemas import UserOwnedEntitySchema
from pydantic import BaseModel, Field, field_validator
from usso_jwt.enums import Algorithm

from server.config import Settings

from .config import TenantConfig, TenantFrontendURLConfig


def _normalize_tenant_domain(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Tenant domain must not be empty")
    has_scheme = "://" in raw
    parsed = urlsplit(raw if has_scheme else f"//{raw}")
    if has_scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Tenant domain URL must use HTTP or HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Tenant domain must not contain URL credentials or query")
    if parsed.path not in {"", "/"} or not parsed.hostname:
        raise ValueError("Tenant domain must contain only host and optional port")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Tenant domain has an invalid port") from exc
    hostname = parsed.hostname.rstrip(".").encode("idna").decode().lower()
    if hostname == "*" or "*" in hostname:
        raise ValueError("Wildcard tenant domains are not supported")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    return f"{hostname}:{port}" if port is not None else hostname


def normalize_tenant_domains(domains: list[str]) -> list[str]:
    """Normalize tenant host[:port] values and reject ambiguous URL parts."""
    if not domains:
        raise ValueError("At least one tenant domain is required")
    normalized: list[str] = []
    for value in domains:
        domain = _normalize_tenant_domain(value)
        if domain not in normalized:
            normalized.append(domain)
    return normalized


def deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge nested dicts; override wins at leaves."""
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = deep_merge_dicts(current, value)
        else:
            merged[key] = value
    return merged


class TenantCreateSchema(BaseModel):
    """
    Schema for creating a new tenant.

    Attributes:
        name: Name of the tenant/organization (2-100 characters).
        domains: List of domains for the tenant's SSO application.
        algorithm: JWT signing algorithm to use (default: Ed25519).

    """

    name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Name of the tenant/organization",
    )

    # Domain Configuration
    domains: list[str] = Field(
        ..., description="The domains of the tenant's SSO application"
    )

    algorithm: Algorithm = Algorithm.Ed25519

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        """Normalize domains used for tenant routing."""
        return normalize_tenant_domains(value)

    @field_validator("algorithm", mode="before")
    @classmethod
    def normalize_algorithm(cls, value: object) -> object:
        """Accept JOSE mixed-case names the same way usso-jwt ``get_algorithm`` does."""
        if isinstance(value, str):
            return value.upper()
        return value


class TenantUpdateSchema(BaseModel):
    """
    Schema for updating an existing tenant.

    All fields are optional. Only provided fields will be updated.

    Attributes:
        name: Updated name of the tenant/organization.
        domains: Updated list of domains.
        is_active: Whether the tenant should be active.

    """

    name: str | None = Field(
        default=None,
        min_length=2,
        max_length=100,
        description="Name of the tenant/organization",
    )
    domains: list[str] | None = Field(
        default=None,
        description="The domains of the tenant's SSO application",
    )
    is_active: bool | None = Field(
        default=None,
        description="Whether the tenant is active",
    )
    config: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Partial tenant config. Nested keys are merged onto the "
            "existing config (other settings are kept)."
        ),
    )

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str] | None) -> list[str] | None:
        """Normalize domains used for tenant routing."""
        return normalize_tenant_domains(value) if value is not None else None


class TenantRetrieveSchema(UserOwnedEntitySchema):
    """
    Schema for retrieving tenant information.

    Includes all tenant data including configuration, frontend URLs,
    and custom JWT payload settings.

    Attributes:
        name: Name of the tenant/organization.
        is_active: Whether the tenant is currently active.
        domains: List of domains associated with the tenant.
        config: Tenant configuration object.
        frontend_urls: Frontend URL configuration.
        custom_payload: Custom JWT payload data.

    """

    name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Name of the tenant/organization",
    )
    is_active: bool = Field(default=True, description="Whether the tenant is active")

    # Domain Configuration
    domains: list[str] = Field(
        ..., description="The domains of the tenant's SSO application"
    )

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, value: list[str]) -> list[str]:
        """Normalize domains loaded from storage and configuration."""
        return normalize_tenant_domains(value)

    # Configuration
    config: TenantConfig = Field(
        default_factory=lambda: TenantConfig(), description="Tenant configuration"
    )
    frontend_urls: TenantFrontendURLConfig = Field(
        default_factory=TenantFrontendURLConfig, description="Tenant frontend URLs"
    )

    def get_frontend_url(self, route: str) -> str:
        """
        Get frontend URL for a specific route.

        Args:
            route: Route name (with or without '_url' suffix).

        Returns:
            Complete frontend URL string.

        """
        if not route.endswith("_url"):
            route = f"{route}_url"
        frontend_endpoint = getattr(self.frontend_urls, route)
        if frontend_endpoint.startswith("http"):
            return frontend_endpoint
        return f"{self.primary_url}{Settings.base_path}{frontend_endpoint}"

    # Custom JWT Payload
    custom_payload: dict | None = Field(
        default=None,
        description="Custom payload for the tenant's identities in jwt",
    )

    @property
    def primary_domain(self) -> str:
        """
        The primary domain for this tenant.

        Returns:
            Primary domain string (first domain by default).

        """
        return getattr(self, "_primary_domain", self.domains[0])

    @primary_domain.setter
    def primary_domain(self, value: str) -> None:
        self._primary_domain = value

    @property
    def primary_url(self) -> str:
        """
        The primary URL for this tenant.

        Returns:
            Primary URL string (http:// for localhost, https:// for others).

        """
        domain = self.primary_domain.rstrip("/")
        if domain.startswith(("http://", "https://")):
            return domain
        if domain == "localhost" or domain.startswith("localhost:"):
            host = domain if ":" in domain else "localhost:8000"
            return f"http://{host}"
        return f"https://{domain}"
