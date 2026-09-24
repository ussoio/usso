"""Pluggable workspace-create verification."""

from __future__ import annotations

import secrets
from abc import ABC, abstractmethod

from usso import UserData

from apps.access_control.workspace.models import Workspace
from apps.identity.user.models import User
from apps.tenant.models import Tenant


class AbstractWorkspaceVerifier(ABC):
    """
    Plugin that can resolve and gate organization workspace create/join.

    Implementations raise ``BadRequestError`` (or similar) when verification fails.
    """

    name: str

    async def ensure_workspace(
        self,
        *,
        tenant: Tenant,
        organization_code: str | None,
        name: str | None = None,
        slug: str | None = None,
    ) -> Workspace:
        """
        Find or create the organization workspace.

        Default implementation does not call external registries. Overlay
        plugins may override this to run organization-details inquiry.
        """
        if organization_code:
            existing = await Workspace.find_one({
                "organization_code": organization_code,
                "tenant_id": tenant.uid,
                "is_deleted": False,
            })
            if existing:
                return existing

        return await Workspace.create_item({
            "tenant_id": tenant.uid,
            "organization_code": organization_code,
            "name": name or organization_code or "workspace",
            "slug": slug or secrets.token_urlsafe(8),
            "is_active": False,
            "meta_data": {"kind": "organization"},
        })

    @abstractmethod
    async def verify_create(
        self,
        *,
        tenant: Tenant,
        user_data: UserData,
        user: User,
        workspace: Workspace,
        organization_code: str | None,
    ) -> None:
        """Validate that the caller may create/join ``workspace``."""
