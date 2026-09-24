"""Schemas for the per-tenant scope catalog."""

from enum import StrEnum

from fastapi_mongo_base.schemas import TenantScopedEntitySchema
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScopeCatalogSource(StrEnum):
    """How a catalog entry was created."""

    SERVICE = "service"
    MANUAL = "manual"


class ScopeCatalogItemIn(BaseModel):
    """One scope declaration in a service sync payload."""

    model_config = ConfigDict(extra="forbid")

    scope: str = Field(..., min_length=1, max_length=512)
    label: str | None = Field(None, max_length=256)
    label_fa: str | None = Field(None, max_length=256)
    description: str | None = Field(None, max_length=1024)

    @field_validator("scope")
    @classmethod
    def normalize_scope(cls, value: str) -> str:
        """Strip whitespace from scope strings."""
        scope = value.strip()
        if not scope:
            raise ValueError("scope must not be empty")
        return scope


class ScopeCatalogSyncSchema(BaseModel):
    """Replace all service-sourced scopes for one service name."""

    scopes: list[ScopeCatalogItemIn] = Field(default_factory=list)


class ScopeCatalogCreateSchema(ScopeCatalogItemIn):
    """Admin/manual catalog entry create payload."""

    service: str = Field(..., min_length=1, max_length=64)
    source: ScopeCatalogSource = ScopeCatalogSource.MANUAL

    @field_validator("service")
    @classmethod
    def normalize_service(cls, value: str) -> str:
        """Normalize service slug."""
        service = value.strip().lower()
        if not service:
            raise ValueError("service must not be empty")
        return service


class ScopeCatalogUpdateSchema(BaseModel):
    """Partial update for a catalog entry (manual edits)."""

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(None, max_length=256)
    label_fa: str | None = Field(None, max_length=256)
    description: str | None = Field(None, max_length=1024)


class ScopeCatalogSchema(TenantScopedEntitySchema):
    """Persisted scope catalog entry."""

    service: str
    scope: str
    action: str | None = None
    resource_path: str | None = None
    label: str | None = None
    label_fa: str | None = None
    description: str | None = None
    source: ScopeCatalogSource = ScopeCatalogSource.SERVICE
