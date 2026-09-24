"""
Role schemas for Pydantic models.

This module defines Pydantic schemas for roles including creation,
updates, and retrieval.
"""

from fastapi_mongo_base.schemas import TenantScopedEntitySchema
from pydantic import BaseModel, ConfigDict, Field


class RoleCreateSchema(BaseModel):
    """
    Schema for creating a new role.

    Attributes:
        name: Role name.
        description: Optional role description.
        scopes: List of permission scopes.
        workspace_id: Optional workspace ID for workspace-specific roles.
        is_active: Whether the role should be active.

    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    scopes: list[str] = Field(default_factory=list)
    is_active: bool = True
    workspace_id: str | None = None


class RoleSchema(RoleCreateSchema, TenantScopedEntitySchema):
    """Schema for role data including tenant scoping."""

    pass


class RoleUpdateSchema(BaseModel):
    """
    Schema for updating an existing role.

    All fields are optional. Only provided fields will be updated.

    Attributes:
        description: Updated role description.
        scopes: Updated list of permission scopes.
        is_active: Updated active status.

    """

    model_config = ConfigDict(extra="forbid")

    description: str | None = None
    scopes: list[str] | None = Field(None)
    is_active: bool | None = None
