"""
Tenant request-time helpers.

Resolve the current tenant from the HTTP request and overlay env-backed
OAuth secrets so login UIs can advertise configured providers.
"""

import os

from fastapi import Request

from apps.tenant.models import Tenant
from apps.tenant.secrets import OAuthSecret
from server.exceptions import BadRequestError


def _configure_oauth_from_env(tenant: Tenant) -> None:
    """Configure OAuth secrets from environment variables."""
    if os.getenv("USSO_GOOGLE_CLIENT_ID") and os.getenv("USSO_GOOGLE_CLIENT_SECRET"):
        tenant.secrets.oauth_secrets["google"] = OAuthSecret(
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
            client_id=os.getenv("USSO_GOOGLE_CLIENT_ID"),
            client_secret=os.getenv("USSO_GOOGLE_CLIENT_SECRET"),
            scopes=["openid", "profile", "email"],
        )


def prepare_tenant_runtime_secrets(tenant: Tenant) -> None:
    """Overlay env-backed OAuth secrets for the current request."""
    _configure_oauth_from_env(tenant)


def list_public_integration_providers(tenant: Tenant) -> list[str]:
    """OAuth providers that login UIs may advertise (config + configured secrets)."""
    prepare_tenant_runtime_secrets(tenant)
    names: set[str] = set(tenant.config.integration.oauth_providers.keys())
    for provider, secret in (tenant.secrets.oauth_secrets or {}).items():
        if getattr(secret, "client_id", None):
            names.add(str(provider))
    return sorted(names)


async def get_tenant(request: Request, *, domain: str | None = None) -> Tenant:
    """
    Get tenant by domain from request.

    Tries request hostname, then hostname:port, then falls back to the
    first available tenant for single-tenant deployments.

    Args:
        request: The FastAPI request object.
        domain: Optional domain string. If not provided, uses request hostname.

    Returns:
        Tenant instance matching the domain.

    Raises:
        ResourceError: If tenant is not found.

    """
    if domain:
        tenant = await Tenant.get_from_domain(domain)
        if tenant:
            return tenant

    hostname = request.url.hostname or ""
    port = request.url.port
    hostname_with_port = f"{hostname}:{port}" if port else hostname

    # Try hostname:port first, then hostname only
    tenant = await Tenant.get_from_domain(hostname_with_port)
    if not tenant and hostname_with_port != hostname:
        tenant = await Tenant.get_from_domain(hostname)

    # Fallback: first available tenant (single-tenant deployments)
    if not tenant:
        tenant = await Tenant.find_one()

    if not tenant:
        raise BadRequestError(
            error_code="tenant_not_found",
            detail="Tenant not found",
            message={"en": "Tenant not found", "fa": "سامانه پیدا نشد."},
        )
    return tenant


async def get_custom_tenant_id(request: Request) -> object | None:
    """
    Extract custom tenant_id from request body.

    Returns:
        Tenant ID from request body if present, None otherwise.

    """
    body: bytes | None = await request.body()
    if body:
        body_json: dict[str, object] = await request.json()
    else:
        body_json = {}
    return body_json.get("tenant_id")


async def get_request_tenant(request: Request) -> Tenant:
    """
    Get tenant from request and require that it is active.

    Args:
        request: The FastAPI request object.

    Returns:
        Active Tenant instance.

    Raises:
        ResourceError: If tenant is not found or not active.

    """
    tenant = await get_tenant(request)

    if not tenant:
        raise BadRequestError(
            error_code="tenant_not_found",
            detail="Tenant not found",
            message={"en": "Tenant not found", "fa": "سامانه پیدا نشد."},
        )
    if not tenant.is_active:
        raise BadRequestError(
            error_code="tenant_not_active",
            detail="Tenant is not active",
            message={"en": "Tenant is not active", "fa": "این سامانه غیرفعال است."},
        )

    return tenant
