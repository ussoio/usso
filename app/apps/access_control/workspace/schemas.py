"""
Workspace schemas for Pydantic models.

This module defines Pydantic schemas for workspaces and workspace invitations.
"""

from datetime import date, datetime
from enum import StrEnum

from fastapi_mongo_base.schemas import (
    TenantScopedEntitySchema,
    TenantUserEntitySchema,
)
from pydantic import BaseModel, Field

from apps.identity.auth.enums import AuthIdentifier
from apps.identity.user.schemas import UserIdentifierSchema


class WorkspaceCreateSchema(BaseModel):
    """
    Schema for creating a new workspace.

    Attributes:
        name: Workspace name.
        organization_code: Optional organization code to link the workspace.
        parent_id: Optional parent workspace for hierarchy (child create).

    """

    name: str
    organization_code: str | None = None
    type: str = Field(default="business", pattern="^(business|personal)$")
    is_active: bool = True
    parent_id: str | None = None


class WorkspaceSchema(WorkspaceCreateSchema, TenantScopedEntitySchema):
    """Schema for workspace data including tenant scoping."""

    slug: str | None = None
    company_data: dict | None = None
    is_active: bool = Field(
        default=True,
        description=(
            "Whether the workspace is active/verified. "
            "Org workspaces become active after verification; "
            "personal workspaces follow tenant config."
        ),
    )
    parent_id: str | None = None
    ancestor_ids: list[str] = Field(default_factory=list)


class WorkspaceMemberSchema(BaseModel):
    """A workspace member with their roles in that workspace."""

    uid: str
    name: str | None = None
    birth_date: date | None = None
    identifiers: list[UserIdentifierSchema] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    is_active: bool = False
    avatar_url: str | None = None


class WorkspaceMemberIdentitySchema(BaseModel):
    """Identity and workspace context for an active workspace member."""

    user_id: str
    workspace_id: str
    user: WorkspaceMemberSchema
    workspace: WorkspaceSchema
    role: str | None = None


class WorkspaceMemberCreateSchema(BaseModel):
    """Directly add a user to a workspace (tenant user-manage)."""

    user_id: str
    role: str = Field(default="member", description="Workspace role to grant")


class WorkspaceLoginBodySchema(BaseModel):
    """Optional body for POST /workspaces/{uid}/login (refresh via cookie or body)."""

    refresh_token: str | None = Field(
        default=None,
        description="Refresh token (optional if sent via cookie)",
    )


class InvitationStatus(StrEnum):
    """Workspace invitation status."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


MAX_INVITATION_EXPIRES_IN_DAYS = 30
DEFAULT_INVITATION_EXPIRES_IN_DAYS = 7


class WorkspaceInvitationCreateSchema(BaseModel):
    """Create a workspace invitation for an existing user."""

    invited_id: str = Field(..., description="User uid to invite")
    role: str = Field(default="member", description="Workspace role to grant on accept")
    expires_in_days: int = Field(
        default=DEFAULT_INVITATION_EXPIRES_IN_DAYS,
        ge=1,
        le=MAX_INVITATION_EXPIRES_IN_DAYS,
        description="Days until the invitation expires (max 30)",
    )


class WorkspaceInvitationUpdateSchema(BaseModel):
    """Accept or reject a pending invitation."""

    status: InvitationStatus = Field(
        ...,
        description="New status; only accepted or rejected are allowed",
    )


class WorkspaceInvitationSchema(TenantUserEntitySchema):
    """Schema for workspace invitation data."""

    workspace_id: str
    invited_id: str
    invited_by: str
    role: str = "member"
    status: InvitationStatus = InvitationStatus.PENDING
    expires_at: datetime
    joined_at: datetime | None = None


class UserSearchResultSchema(BaseModel):
    """Minimal user payload returned from identifier prefix search."""

    uid: str
    name: str | None = None
    avatar_url: str | None = None
    matched_type: AuthIdentifier
    matched_identifier: str
