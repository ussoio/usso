"""
Role database models.

This module defines the Role model for access control within tenants.
Roles can be tenant-wide (workspace_id is None) or scoped to a workspace.
"""

from fastapi_mongo_base.models import TenantScopedEntity

from .schemas import RoleSchema


class Role(RoleSchema, TenantScopedEntity):
    """
    Role model for access control.

    Represents a role with associated scopes and permissions within a tenant.
    When workspace_id is set, the role applies only to that workspace;
    when None, it is tenant-wide.
    """

    @classmethod
    def get_queryset(cls, **kwargs: object) -> dict:
        """Get queryset with optional workspace scoping."""
        workspace_id = kwargs.pop("workspace_id", None)
        workspace_id_in = kwargs.pop("workspace_id_in", None)
        queryset = super().get_queryset(**kwargs)
        if workspace_id_in is not None:
            or_conditions = [{"workspace_id": w} for w in workspace_id_in]
            if or_conditions:
                queryset["$or"] = or_conditions
        elif workspace_id is not None:
            queryset["$or"] = [
                # {"workspace_id": None},  # ruff:ignore[commented-out-code]
                {"workspace_id": workspace_id},
            ]
        else:
            queryset["workspace_id"] = None
        return queryset
