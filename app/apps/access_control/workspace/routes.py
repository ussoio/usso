"""
Workspace management API routes.

This module provides endpoints for managing workspaces within tenants,
including creation, updates, invitations, and member search.
"""

import logging

from fastapi import APIRouter, Body, Query, Request, Response, status
from fastapi_mongo_base.schemas import PaginatedResponse
from usso import UserData, USSOException, authorization

from apps.access_control.workspace import services
from apps.identity.auth.enums import AuthIdentifier
from apps.identity.auth.schemas import RefreshResponse
from apps.identity.auth.services import (
    build_workspace_switch_response,
    check_session_validity,
)
from apps.identity.user.models import User
from apps.tenant.services import get_request_tenant
from server.config import Settings
from server.exceptions import BadRequestError, ForbiddenError, UnauthorizedError
from utils.net import get_client_ip
from utils.usso_routes import AbstractTenantUSSORouter

from . import models, schemas

logger = logging.getLogger(__name__)


class WorkspaceRouter(AbstractTenantUSSORouter):
    """
    Router for workspace management endpoints.

    Provides CRUD operations for workspaces with tenant scoping and
    USSO authentication.
    """

    namespace = "sso"
    resource = "workspace"

    @property
    def resource_path(self) -> str:
        """Authorize path: namespace/project/resource → ``sso/usso/workspace``."""
        return "sso/usso/workspace"

    def config_routes(self, **kwargs: object) -> None:
        """Configure routes."""
        super().config_routes(mine_route=True, **kwargs)
        # Membership-oriented create (alongside GET /mine). Register before
        # /{uid} routes so "mine" is never captured as a workspace uid.
        self.router.add_api_route(
            "/mine",
            self.create_mine_item,
            methods=["POST"],
            response_model=self.schema,
            status_code=201,
        )
        self.router.add_api_route(
            "/{uid}/users",
            self.list_workspace_users,
            methods=["GET"],
            response_model=PaginatedResponse[schemas.WorkspaceMemberSchema],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/users/search",
            self.search_workspace_users,
            methods=["GET"],
            response_model=PaginatedResponse[schemas.UserSearchResultSchema],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/login",
            self.login_workspace,
            methods=["POST"],
            response_model=RefreshResponse,
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/members",
            self.add_workspace_member,
            methods=["POST"],
            response_model=schemas.WorkspaceMemberSchema,
            status_code=201,
        )
        self.router.add_api_route(
            "/{uid}/members/{user_id}",
            self.remove_workspace_member,
            methods=["DELETE"],
            status_code=204,
        )
        self.router.add_api_route(
            "/{uid}/members/{user_id}",
            self.get_workspace_member_identity,
            methods=["GET"],
            response_model=schemas.WorkspaceMemberIdentitySchema,
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/invitations",
            self.create_workspace_invitation,
            methods=["POST"],
            response_model=schemas.WorkspaceInvitationSchema,
            status_code=201,
        )
        self.router.add_api_route(
            "/{uid}/invitations",
            self.list_workspace_invitations,
            methods=["GET"],
            response_model=PaginatedResponse[schemas.WorkspaceInvitationSchema],
            status_code=200,
        )

    model = models.Workspace
    schema = schemas.WorkspaceSchema

    def get_list_filter_queries(self, *, user: UserData) -> dict:
        """Build list query filters from user and scopes."""
        matched_scopes: list[dict] = authorization.get_scope_filters(
            action="read",
            resource=self.resource_path,
            user_scopes=user.scopes if user else [],
        )
        return authorization.broadest_scope_filter(matched_scopes)

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        workspace_type: str | None = Query(
            None,
            alias="type",
            pattern="^(business|personal)$",
        ),
        name_like: str | None = Query(None),
        organization_code_like: str | None = Query(None),
        is_active: bool | None = Query(None),
    ) -> PaginatedResponse[schemas.WorkspaceSchema]:
        """
        List workspaces.

        Admins see all in the tenant. Other users see only active workspaces
        in their ``workspace_ids`` (inactive memberships, e.g. pending personal
        workspaces, are hidden — same default as ``mine_items``).
        """
        if workspace_type not in {"business", "personal"}:
            workspace_type = None
        user_data = await self.get_user(request)
        user = await User.get_by_uid(user_data.uid)
        # Tenant admins (``admin`` or
        # unscoped workspace read/manage) list every workspace.
        # Membership-only users are limited to ``user.workspace_ids``.
        extra: dict[str, object] = {}
        if workspace_type:
            extra["type"] = workspace_type
        if isinstance(name_like, str) and name_like.strip():
            extra["name_like"] = name_like.strip()
        if isinstance(organization_code_like, str) and organization_code_like.strip():
            extra["organization_code_like"] = organization_code_like.strip()
        if isinstance(is_active, bool):
            extra["is_active"] = is_active
        if services.can_list_tenant_workspaces(user=user, user_data=user_data):
            return await self._list_items(
                request=request,
                offset=offset,
                limit=limit,
                **extra,
            )
        workspace_ids = list(user.workspace_ids or []) if user else []
        member_extra = {
            key: value for key, value in extra.items() if key != "is_active"
        }
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            uid__in=workspace_ids,
            is_active=True,
            **member_extra,
        )

    async def mine_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        is_active: bool = Query(
            True,
            description=(
                "Only return workspaces with this is_active value. "
                "Defaults to true so inactive personal workspaces are hidden."
            ),
        ),
    ) -> PaginatedResponse:
        """
        Get workspaces the current user belongs to.

        By default only active workspaces are returned (``is_active=true``).
        Pass ``is_active=false`` to list inactive ones (e.g. personal workspaces
        waiting for verification).
        """
        user_data = await self.get_user(request)
        user = await User.get_by_uid(user_data.uid)
        workspace_ids = list(user.workspace_ids or []) if user else []
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            uid__in=workspace_ids,
            is_active=is_active,
        )

    def _require_workspace_enabled(self, tenant: object) -> None:
        if not tenant.config.workspace.enabled:
            raise BadRequestError(
                error_code="workspace_not_enabled",
                detail="Workspace is not enabled for this tenant.",
                message={
                    "en": "Workspace is not enabled for this tenant.",
                    "fa": "قابلیت فضای کاری در این سامانه فعال نیست.",
                },
            )

    def _require_member_create_allowed(
        self, *, tenant: object, user_data: UserData
    ) -> None:
        if tenant.config.workspace.allow_member_create:
            return
        if services.has_system_workspace_admin(user_scopes=user_data.scopes or []):
            return
        raise BadRequestError(
            error_code="workspace_member_create_disabled",
            detail="Member workspace creation is disabled for this tenant.",
            message={
                "en": (
                    "Creating a workspace is not allowed. Contact an administrator."
                ),
                "fa": "ایجاد فضای کاری مجاز نیست. با مدیر سامانه تماس بگیرید.",
            },
        )

    async def create_item(
        self, request: Request, data: schemas.WorkspaceCreateSchema
    ) -> models.Workspace:
        """
        Create a workspace in the tenant catalog.

        Unscoped workspace admins provision without joining (no
        ``workspace_ids`` update). Other callers still join for backward
        compatibility; prefer ``POST /workspaces/mine`` for self-create.
        """
        tenant = await self.get_tenant(request)
        self._require_workspace_enabled(tenant)
        user_data = await self.get_user(request)
        item = schemas.WorkspaceSchema(
            **data.model_dump(), tenant_id=user_data.tenant_id
        )
        if services.has_system_workspace_admin(user_scopes=user_data.scopes or []):
            return await services.create_workspace_provision(
                user_data=user_data, item=item
            )
        self._require_member_create_allowed(tenant=tenant, user_data=user_data)
        return await services.create_workspace(user_data, item)

    async def create_mine_item(
        self, request: Request, data: schemas.WorkspaceCreateSchema
    ) -> models.Workspace:
        """
        Create a workspace and add it to the caller's memberships.

        Stable self-create path paired with ``GET /workspaces/mine``.
        """
        tenant = await self.get_tenant(request)
        self._require_workspace_enabled(tenant)
        user_data = await self.get_user(request)
        self._require_member_create_allowed(tenant=tenant, user_data=user_data)
        return await services.create_workspace(
            user_data,
            schemas.WorkspaceSchema(**data.model_dump(), tenant_id=user_data.tenant_id),
        )

    async def retrieve_item(self, request: Request, uid: str) -> models.Workspace:
        """Retrieve a workspace."""
        user = await self.get_user(request)
        item = await self.get_item(
            uid=uid, tenant_id=user.tenant_id, **{self.owner_attr: None}
        )
        owner_id = self.get_owner_id(user)
        await self.authorize(
            action="read",
            user=user,
            filter_data={"owner_id": owner_id},
        )
        return item

    async def list_workspace_users(
        self,
        request: Request,
        uid: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
    ) -> PaginatedResponse[schemas.WorkspaceMemberSchema]:
        """List users in a workspace with their workspace-scoped roles."""
        user = await self.get_user(request)
        await self.get_item(
            uid=uid, tenant_id=user.tenant_id, **{self.owner_attr: None}
        )
        await self.authorize(
            action="read",
            user=user,
            filter_data={"uid": uid, "workspace_id": uid},
        )
        items, total = await services.list_workspace_members(
            workspace_id=uid,
            tenant_id=user.tenant_id,
            offset=offset,
            limit=limit,
        )
        return PaginatedResponse(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
        )

    async def get_workspace_member_identity(
        self,
        request: Request,
        uid: str,
        user_id: str,
    ) -> schemas.WorkspaceMemberIdentitySchema:
        """Return identity and workspace context for one authenticated member."""
        user = await self.get_user(request)
        await self.get_item(
            uid=uid,
            tenant_id=user.tenant_id,
            **{self.owner_attr: None},
        )
        if (user.claims or {}).get("sub_type") == "agent":
            if not authorization.check_access(
                user_scopes=user.scopes or [],
                resource_path="sso/usso/workspace",
                action="read",
            ):
                raise ForbiddenError(
                    error_code="workspace_identity_denied",
                    detail="Agent cannot read workspace member identity",
                    message={"en": "Access denied.", "fa": "دسترسی ندارید."},
                )
        else:
            await self.authorize(
                action="read",
                user=user,
                filter_data={"uid": uid, "workspace_id": uid},
            )
        return await services.get_workspace_member_identity(
            workspace_id=uid,
            user_id=user_id,
            tenant_id=user.tenant_id,
        )

    async def search_workspace_users(
        self,
        request: Request,
        uid: str,
        identifier: str = Query(..., min_length=2),
        identifier_type: AuthIdentifier | None = Query(None),
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
    ) -> PaginatedResponse[schemas.UserSearchResultSchema]:
        """Prefix-search searchable users for inviting into this workspace."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        items, total = await services.search_users_by_identifier_prefix(
            tenant=tenant,
            user_data=user_data,
            workspace_id=uid,
            identifier=identifier,
            identifier_type=identifier_type,
            offset=offset,
            limit=limit,
        )
        return PaginatedResponse(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
        )

    async def login_workspace(
        self,
        request: Request,
        uid: str,
        data: schemas.WorkspaceLoginBodySchema | None = Body(default=None),
    ) -> Response:
        """
        Switch the current session into workspace ``uid``.

        Alias of ``POST /auth/workspace-login`` with workspace id in the path.
        Requires a valid refresh token (cookie or body).
        """
        body = data or schemas.WorkspaceLoginBodySchema()
        try:
            tenant = await get_request_tenant(request)
            if body.refresh_token:
                refresh_payload = tenant.refresh_auth.user_data_from_token(
                    body.refresh_token,
                    raise_exception=True,
                    expected_token_type="refresh",  # ruff:ignore[hardcoded-password-func-arg]
                )
            else:
                refresh_payload = tenant.refresh_auth(request)
            if not refresh_payload:
                raise UnauthorizedError(
                    error_code="refresh_token_required",
                    detail="Refresh token required (cookie or body)",
                    message={
                        "en": "Refresh token required",
                        "fa": "لطفاً دوباره وارد شوید.",
                    },
                )
            session = await check_session_validity(refresh_payload=refresh_payload)
            return await build_workspace_switch_response(
                request=request,
                tenant=tenant,
                payload=refresh_payload,
                session=session,
                workspace_id=uid,
                user_agent=request.headers.get("user-agent"),
                ip=get_client_ip(request),
            )
        except USSOException:
            logger.exception("Workspace path login failed.")
            raise

    async def add_workspace_member(
        self,
        request: Request,
        uid: str,
        data: schemas.WorkspaceMemberCreateSchema,
    ) -> schemas.WorkspaceMemberSchema:
        """Directly add a member (tenant manage:sso/usso/member)."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        return await services.add_workspace_member(
            tenant=tenant,
            user_data=user_data,
            workspace_id=uid,
            target_user_id=data.user_id,
            role=data.role,
        )

    async def remove_workspace_member(
        self,
        request: Request,
        uid: str,
        user_id: str,
    ) -> Response:
        """Remove a member (tenant manage:sso/usso/member)."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        await services.remove_workspace_member(
            tenant=tenant,
            user_data=user_data,
            workspace_id=uid,
            target_user_id=user_id,
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    async def create_workspace_invitation(
        self,
        request: Request,
        uid: str,
        data: schemas.WorkspaceInvitationCreateSchema,
    ) -> models.WorkspaceInvitation:
        """Invite a user into this workspace."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        return await services.create_workspace_invitation(
            tenant=tenant,
            user_data=user_data,
            workspace_id=uid,
            data=data,
        )

    async def list_workspace_invitations(
        self,
        request: Request,
        uid: str,
        status: schemas.InvitationStatus | None = Query(None),
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
    ) -> PaginatedResponse[schemas.WorkspaceInvitationSchema]:
        """List invitations for this workspace."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        items, total = await services.list_workspace_invitations(
            tenant=tenant,
            user_data=user_data,
            workspace_id=uid,
            status=status,
            offset=offset,
            limit=limit,
        )
        return PaginatedResponse(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
        )


class InvitationRouter(AbstractTenantUSSORouter):
    """Router for the current user's workspace invitations."""

    model = models.WorkspaceInvitation
    schema = schemas.WorkspaceInvitationSchema
    resource = "workspace_invitation"

    def __init__(self) -> None:
        """Initialize invitation routes under /invitations."""
        super().__init__(
            prefix="/invitations",
            tags=["Workspace Invitations"],
        )

    def config_routes(self, **kwargs: object) -> None:
        """Only list (mine via auth) and respond; no generic CRUD."""
        self.router.add_api_route(
            "",
            self.list_items,
            methods=["GET"],
            response_model=PaginatedResponse[schemas.WorkspaceInvitationSchema],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid:str}",
            self.update_item,
            methods=["PATCH"],
            response_model=schemas.WorkspaceInvitationSchema,
            status_code=200,
        )

    async def list_items(
        self,
        request: Request,
        status: schemas.InvitationStatus | None = Query(None),
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
    ) -> PaginatedResponse[schemas.WorkspaceInvitationSchema]:
        """List invitations addressed to the authenticated user."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        items, total = await services.list_my_invitations(
            tenant=tenant,
            user_data=user_data,
            status=status,
            offset=offset,
            limit=limit,
        )
        return PaginatedResponse(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
        )

    async def update_item(
        self,
        request: Request,
        uid: str,
        data: schemas.WorkspaceInvitationUpdateSchema,
    ) -> models.WorkspaceInvitation:
        """Accept or reject an invitation addressed to the current user."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        return await services.respond_to_invitation(
            tenant=tenant,
            user_data=user_data,
            invitation_uid=uid,
            status=data.status,
        )


workspace_router = WorkspaceRouter().router
invitation_router = InvitationRouter().router

router = APIRouter()
router.include_router(workspace_router)
router.include_router(invitation_router)
