"""Seed USSO's own scopes into each tenant catalog at startup."""

from __future__ import annotations

import logging

from usso.scope_catalog import scopes_from_resource_paths

from apps.tenant.config import TenantConfig
from apps.tenant.models import Tenant

from . import schemas, services

logger = logging.getLogger(__name__)

SSO_CATALOG_SERVICE = "sso"
SSO_CATALOG_ACTIONS = ("read", "manage", "admin")

# Default router path is namespace/service/resource (sso/usso/...).
CORE_RESOURCE_PATHS = (
    "sso/usso/user",
    "sso/usso/identifier",
    "sso/usso/credential",
    "sso/usso/role",
    "sso/usso/session",
    "sso/usso/profile",
    "sso/usso/legal_document",
    "sso/usso/legal_acceptance",
    "sso/usso/scope_catalog",
)

WORKSPACE_RESOURCE_PATHS = (
    "sso/usso/workspace",
    "sso/usso/workspace_invitation",
    "sso/usso/member",
)

AGENT_RESOURCE_PATHS = ("sso/usso/agent",)
API_KEY_RESOURCE_PATHS = ("sso/usso/apikey",)

SCOPE_LABELS: dict[str, dict[str, str]] = {
    "manage:sso/usso/user": {
        "label": "Manage users",
        "label_fa": "مدیریت کاربران",
        "description": "Create and update users without impersonation",
    },
    "admin:sso/usso/user": {
        "label": "Impersonate users",
        "label_fa": "ورود به حساب کاربران",
        "description": "Impersonate users (also grants user management)",
    },
    "manage:sso/usso/member": {
        "label": "Manage workspace members",
        "label_fa": "مدیریت اعضای فضای کاری",
        "description": "Add or remove workspace members directly",
    },
    "manage:sso/usso/workspace": {
        "label": "Manage workspaces",
        "label_fa": "مدیریت فضاهای کاری",
    },
    "admin:sso/usso/workspace": {
        "label": "Administer workspaces",
        "label_fa": "اداره فضاهای کاری",
        "description": "Enter workspaces without membership",
    },
}


def resource_paths_for_tenant(config: TenantConfig) -> list[str]:
    """Resource paths to publish for one tenant, based on feature flags."""
    paths = list(CORE_RESOURCE_PATHS)
    if config.workspace.enabled:
        paths.extend(WORKSPACE_RESOURCE_PATHS)
    if config.agents.enabled:
        paths.extend(AGENT_RESOURCE_PATHS)
    if config.integration.api_key.enabled:
        paths.extend(API_KEY_RESOURCE_PATHS)
    return paths


def build_usso_catalog_items(
    config: TenantConfig | None = None,
) -> list[schemas.ScopeCatalogItemIn]:
    """Build catalog sync items for USSO itself."""
    cfg = config or TenantConfig()
    raw = scopes_from_resource_paths(
        resource_paths_for_tenant(cfg),
        actions=SSO_CATALOG_ACTIONS,
        labels=SCOPE_LABELS,
    )
    return [schemas.ScopeCatalogItemIn.model_validate(item) for item in raw]


async def register_usso_scope_catalog() -> None:
    """
    Sync USSO scopes into every tenant catalog (best-effort).

    Writes via ``sync_service_scopes`` (no HTTP self-call). Feature-gated by
    each tenant's config (workspace, agents, api_key).
    """
    try:
        tenants = await Tenant.find({"is_deleted": False}).to_list()
    except Exception:
        logger.exception("Failed to list tenants for USSO scope catalog seed")
        return

    for tenant in tenants:
        try:
            items = build_usso_catalog_items(tenant.config)
            await services.sync_service_scopes(
                tenant_id=tenant.uid,
                service=SSO_CATALOG_SERVICE,
                items=items,
            )
            logger.info(
                "Seeded %s USSO catalog scopes for tenant=%s",
                len(items),
                tenant.uid,
            )
        except Exception:
            logger.exception(
                "Failed to seed USSO scope catalog for tenant=%s",
                tenant.uid,
            )
