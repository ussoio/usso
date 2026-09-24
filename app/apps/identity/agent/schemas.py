"""Agent schemas."""

from datetime import datetime
from typing import Literal, Self

from fastapi_mongo_base.schemas import TenantScopedEntitySchema
from pydantic import BaseModel, Field, field_validator, model_validator
from usso_jwt.enums import Algorithm

from server.exceptions import NotFoundError


class AgentCreateSchema(BaseModel):
    """Agent create schema."""

    name: str
    description: str | None = None
    user_id: str | None = None
    workspace_id: str | None = None
    scopes: list[str]
    alg: Algorithm = Algorithm.Ed25519
    verify_key: str | None = None

    @field_validator("alg", mode="before")
    @classmethod
    def normalize_alg(cls, value: object) -> object:
        """Accept JOSE mixed-case names the same way usso-jwt ``get_algorithm`` does."""
        if isinstance(value, str):
            return value.upper()
        return value

    @field_validator("alg")
    @classmethod
    def reject_symmetric_signing_algorithms(cls, value: Algorithm) -> Algorithm:
        """Agent verification keys must never double as shared signing secrets."""
        if value.kty == "oct":
            raise ValueError("Agent JWT algorithms must be asymmetric")
        return value


class AgentUpdateSchema(BaseModel):
    """Agent update schema."""

    description: str | None = None
    scopes: list[str] | None = None
    is_active: bool | None = None


class AgentSchema(AgentCreateSchema, TenantScopedEntitySchema):
    """Agent schema — subject is user_id and/or workspace_id (DB model)."""

    is_active: bool = True
    last_used_at: datetime | None = None
    hashed_client_secret: str | None = None
    created_by: str | None = None
    kid: str | None = None

    @model_validator(mode="after")
    def validate_subject_at_least_one(self) -> Self:
        """Require at least one of user_id or workspace_id."""
        if self.user_id is None and self.workspace_id is None:
            msg = "At least one of user_id or workspace_id must be set"
            raise ValueError(msg)
        return self

    def get_client_id(self) -> str:
        """Get client ID."""
        return self.uid

    async def get_config_response(self) -> dict[str, object]:
        """Get config response."""
        from apps.tenant.models import Tenant
        from server.config import Settings

        if not hasattr(self, "_tenant"):
            self._tenant = await Tenant.get_by_uid(self.tenant_id)

        if not self._tenant:
            raise NotFoundError(
                detail="Tenant not found",
                message={
                    "en": "The request is not valid for any tenant.",
                    "fa": "درخواست شما در هیچ سامانه‌ای معتبر نیست.",
                },
            )

        base_url = f"{self._tenant.primary_url or ''}{Settings.base_path}"
        return {
            "type": "agent",
            "client_id": self.get_client_id(),
            "client_email": f"{self.name}@{self._tenant.primary_domain or ''}",
            "auth_uri": f"{base_url}/agents/auth",
            "token_uri": f"{base_url}/oauth/token",
            "universe_domain": self._tenant.primary_domain or "",
        }


class AgentResponseSchema(TenantScopedEntitySchema):
    """Public agent response — never exposes hashed_client_secret."""

    name: str
    description: str | None = None
    user_id: str | None = None
    workspace_id: str | None = None
    scopes: list[str]
    alg: Algorithm = Algorithm.Ed25519
    verify_key: str | None = None
    kid: str | None = None
    is_active: bool = True
    last_used_at: datetime | None = None
    created_by: str | None = None


class AgentCreateResponse(AgentResponseSchema):
    """Agent create response schema."""

    type: Literal["agent"] = "agent"
    private_key: str | None = None
    client_secret: str | None = None
    client_email: str | None = None
    client_id: str

    auth_uri: str | None = None
    token_uri: str | None = None
    auth_provider_x509_cert_url: str | None = None
    client_x509_cert_url: str | None = None
    universe_domain: str | None = None

    def model_dump(self, **kwargs: object) -> dict[str, object]:
        """Dump model to dict."""
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)


class AgentAuthPayload(BaseModel):
    """Agent auth payload schema."""

    iss: str | None = None
    jti: str = Field(..., min_length=16, max_length=256)
    iat: int
    exp: int
    scopes: list[str]
    aud: str | None = None
    tenant_id: str
