"""
Workspace database models.

This module defines models for workspaces and workspace invitations
within the access control system.
"""

import re
from typing import ClassVar

from fastapi_mongo_base.models import (
    ASCENDING,
    IndexModel,
    TenantScopedEntity,
    TenantUserEntity,
)

from .schemas import WorkspaceInvitationSchema, WorkspaceSchema


class Workspace(WorkspaceSchema, TenantScopedEntity):
    """
    Workspace model for organizing resources within a tenant.

    Each workspace has a unique slug within a tenant and can contain
    various resources and settings. Hierarchy uses parent_id + ancestor_ids.
    """

    @classmethod
    def get_queryset(cls, **kwargs: object) -> dict:
        """Get queryset with optional uid__in, type, and admin search filters."""
        uid_in = kwargs.pop("uid__in", None)
        workspace_type = kwargs.pop("type", None)
        name_like = kwargs.pop("name_like", None)
        organization_code_like = kwargs.pop("organization_code_like", None)
        queryset = super().get_queryset(**kwargs)
        if uid_in is not None:
            queryset["uid"] = {"$in": list(uid_in)}
        if workspace_type == "personal":
            queryset["$or"] = [
                {"type": "personal"},
                {"meta_data.kind": "personal"},
            ]
        elif workspace_type == "business":
            # Legacy business workspaces predate the explicit type field.
            queryset["type"] = {"$ne": "personal"}
            queryset["meta_data.kind"] = {"$ne": "personal"}
        if isinstance(name_like, str) and name_like.strip():
            queryset["name"] = {
                "$regex": re.escape(name_like.strip()),
                "$options": "i",
            }
        if isinstance(organization_code_like, str) and organization_code_like.strip():
            queryset["organization_code"] = {
                "$regex": re.escape(organization_code_like.strip()),
            }
        return queryset

    @property
    def is_personal(self) -> bool:
        """True when this is a personal workspace (uid == user.uid)."""
        meta = self.meta_data or {}
        return meta.get("kind") == "personal"

    class Settings:
        """
        Workspace model settings.

        Configures database indexes and validation behavior.
        """

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantScopedEntity.Settings.indexes,
            IndexModel([("tenant_id", ASCENDING), ("slug", ASCENDING)], unique=True),
            IndexModel([("tenant_id", ASCENDING), ("parent_id", ASCENDING)]),
            IndexModel([("tenant_id", ASCENDING), ("ancestor_ids", ASCENDING)]),
        ]


class WorkspaceInvitation(WorkspaceInvitationSchema, TenantUserEntity):
    """
    Workspace invitation model.

    Represents an invitation for a user to join a workspace.
    """

    pass
