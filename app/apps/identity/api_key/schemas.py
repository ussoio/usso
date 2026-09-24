"""API key schemas."""

import uuid
from datetime import datetime
from typing import Self

from fastapi_mongo_base.schemas import TenantScopedEntitySchema
from fastapi_mongo_base.utils import timezone
from pydantic import BaseModel, Field, model_validator


class RevokeAPIKeySchema(BaseModel):
    """Revoke API key schema."""

    revoked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.tz))
    revoked_by: str = Field(..., description="The user who revoked the key")
    revoked_reason: str | None = Field(
        None, description="The reason for revoking the key"
    )


class APIKeyCreateSchema(BaseModel):
    """API key create schema."""

    name: str | None = None
    description: str | None = None
    user_id: str | None = None
    workspace_id: str | None = None
    scopes: list[str] = Field(default_factory=list)

    ip_whitelist: list[str] = Field(
        default_factory=list,
        description=("If non-empty, only these client IPs may use the API key."),
    )
    rate_limit: dict = Field(
        default_factory=dict,
        description=(
            'Per-key rate limit, e.g. {"requests": 60, "window_seconds": 60}. '
            "Empty means unlimited."
        ),
    )
    expires_at: datetime | None = None


class APIKeySchema(APIKeyCreateSchema, TenantScopedEntitySchema):
    """API key schema — subject is user_id and/or workspace_id."""

    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))

    api_key_pattern: str
    hashed_key: str
    hashed_client_secret: str | None = None
    created_by: str | None = None
    revoked: RevokeAPIKeySchema | None = None

    is_active: bool = True

    last_used_at: datetime | None = Field(
        None,
        description="The last time the API key was used.",
    )
    usage_count: int = Field(
        0,
        description="The number of times the API key has been used.",
    )
    last_ip: str | None = Field(
        None,
        description="The last IP address used to access the API key.",
    )
    last_user_agent: str | None = Field(
        None,
        description="The last user agent used to access the API key.",
    )

    @model_validator(mode="after")
    def validate_subject_at_least_one(self) -> Self:
        """Require at least one of user_id or workspace_id."""
        if self.user_id is None and self.workspace_id is None:
            msg = "At least one of user_id or workspace_id must be set"
            raise ValueError(msg)
        return self


class APIKeyResponseSchema(TenantScopedEntitySchema):
    """API key response schema."""

    name: str | None = None
    description: str | None = None
    user_id: str | None = None
    workspace_id: str | None = None
    created_by: str | None = None
    client_id: str | None = None
    api_key_pattern: str
    scopes: list[str] = Field(default_factory=list)
    is_active: bool = True
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    usage_count: int = 0
    rate_limit: dict = Field(default_factory=dict)


class APIKeyCreateResponseSchema(APIKeyResponseSchema):
    """API key create response schema."""

    api_key: str = Field(..., description="Bearer API key (shown once)")
    client_secret: str = Field(
        ...,
        description="OAuth client_secret for /oauth/token (shown once)",
    )


class APIKeyVerifySchema(BaseModel):
    """API key verify schema."""

    api_key: str
