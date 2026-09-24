"""
Role management API routes.

This module provides endpoints for managing roles within tenants,
including creation and updates with scope validation.
Roles can be tenant-wide (workspace_id is None) or scoped to a workspace.
"""

from fastapi import Query, Request
from fastapi_mongo_base.schemas import PaginatedResponse
from usso import authorization

from apps.identity.auth.services import require_secure_token
from apps.identity.user.models import User
from server.config import Settings
from server.exceptions import ForbiddenError
from utils.usso_routes import AbstractTenantUSSORouter

from . import models, schemas


class RoleRouter(AbstractTenantUSSORouter):
    """
    Router for role management endpoints.

    Provides CRUD operations for roles with tenant scoping and
    USSO authentication.
    """

    model = models.Role
    schema = schemas.RoleSchema
    resource = "role"

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        workspace_id: str | None = Query(
            None,
            description="Filter by workspace (tenant-wide only, or + this workspace)",
        ),
    ) -> PaginatedResponse[schemas.RoleSchema]:
        """List roles, optionally scoped to a workspace."""
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            workspace_id=workspace_id,
        )

    async def create_item(
        self, request: Request, data: schemas.RoleCreateSchema
    ) -> models.Role:
        """
        Create a new role.

        Args:
            request: The FastAPI request object.
            data: Role creation schema data.

        Returns:
            Created Role instance.

        Note:
            Scopes must be a subset of the caller's scopes. Optional soft checks
            against tenant ``scope_catalog`` are not enforced so undeclared
            service scopes remain backward-compatible.

        """
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        await self.authorize(action="create", user=user, filter_data=data.model_dump())
        user_model = await User.get_item(uid=user.uid, tenant_id=user.tenant_id)
        if user_model and data.scopes:
            scope_context = data.workspace_id
            user_scopes = await user_model.get_scopes(scope_context) or []
            for scope in data.scopes:
                if not authorization.has_subset_scope(
                    subset_scope=scope, user_scopes=user_scopes
                ):
                    detail = (
                        f"You cannot create a role with scopes you don't have: {scope}"
                    )
                    raise ForbiddenError(
                        error_code="scope_insufficient",
                        detail=detail,
                        message={
                            "en": detail,
                            "fa": (
                                "فقط می‌توانید دسترسی‌هایی را تعریف کنید "
                                f"که خودتان دارید: {scope}."
                            ),
                        },
                    )
        return await super().create_item(request, data)

    async def update_item(
        self, request: Request, uid: str, data: schemas.RoleUpdateSchema
    ) -> models.Role:
        """
        Update an existing role.

        Args:
            request: The FastAPI request object.
            uid: Unique identifier of the role to update.
            data: Role update schema data.

        Returns:
            Updated Role instance.

        Note:
            Scopes must be a subset of the caller's scopes. Catalog membership
            is intentionally not required (soft / optional for UI only).

        """
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        item = await self.get_item(uid=uid, user_id=None, tenant_id=user.tenant_id)
        await self.authorize(action="update", user=user, filter_data=item.model_dump())
        data_dict = data.model_dump(exclude_none=True)
        if "scopes" in data_dict:
            user_model = await User.get_item(uid=user.uid, tenant_id=user.tenant_id)
            if user_model:
                scope_context = item.workspace_id
                user_scopes = await user_model.get_scopes(scope_context) or []
                for scope in data_dict["scopes"]:
                    if not authorization.has_subset_scope(
                        subset_scope=scope, user_scopes=user_scopes
                    ):
                        detail = f"You cannot assign scopes you don't have: {scope}"
                        fa_detail = (
                            f"فقط می‌توانید دسترسی‌هایی بدهید که خودتان دارید: {scope}."
                        )
                        raise ForbiddenError(
                            error_code="scope_insufficient",
                            detail=detail,
                            message={"en": detail, "fa": fa_detail},
                        )
        item = await super().update_item(request, uid, data_dict)
        if "scopes" in data_dict or "is_active" in data_dict:
            await User.propagate_role_scope_change(
                tenant_id=item.tenant_id,
                role_name=item.name,
                role_workspace_id=item.workspace_id,
            )
        return item

    async def delete_item(self, request: Request, uid: str) -> models.Role:
        """Delete a role and immediately remove its effective permissions."""
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        item = await super().delete_item(request, uid)
        await User.propagate_role_scope_change(
            tenant_id=item.tenant_id,
            role_name=item.name,
            role_workspace_id=item.workspace_id,
        )
        return item


router = RoleRouter().router
