"""Legal document and acceptance schemas."""

from datetime import datetime
from enum import StrEnum
from typing import Self

from fastapi_mongo_base.schemas import TenantScopedEntitySchema, TenantUserEntitySchema
from pydantic import BaseModel, Field, computed_field, model_validator


class LegalDocumentType(StrEnum):
    """Types of legal documents managed per tenant."""

    TERMS = "terms"
    PRIVACY_POLICY = "privacy_policy"
    SERVICE_CONTRACT = "service_contract"
    REFUND_POLICY = "refund_policy"
    COOKIE_POLICY = "cookie_policy"
    IMPRINT = "imprint"


class LegalSubjectScope(StrEnum):
    """Who must accept a legal document."""

    USER = "user"
    WORKSPACE = "workspace"


class LegalAcceptanceSource(StrEnum):
    """Where the acceptance was captured."""

    SIGNUP = "signup"
    LOGIN = "login"
    CHECKOUT = "checkout"
    KYC = "kyc"
    ADMIN = "admin"
    WORKSPACE_SIGNUP = "workspace_signup"


class LegalDocumentCreateSchema(BaseModel):
    """Schema for publishing a new legal document version."""

    document_type: LegalDocumentType = Field(..., description="Document category.")
    subject_scope: LegalSubjectScope = Field(
        default=LegalSubjectScope.USER,
        description="Whether the user or a workspace must accept this document.",
    )
    version: str = Field(description="Version label, e.g. 2026-06-15 or v3.")
    title: str = Field(..., description="Human-readable title.")
    content: str = Field(..., description="The document content in markdown format.")
    attachment_url: str | None = Field(
        default=None, description="URL where the document attachment is hosted."
    )
    is_active: bool = Field(
        default=True, description="Whether this version is currently offered."
    )
    requires_reacceptance: bool = Field(
        default=True,
        description=(
            "If true, subjects must accept this version even if they accepted "
            "a prior one."
        ),
    )
    effective_at: datetime | None = Field(
        default=None,
        description="When this version becomes effective. Defaults to created_at.",
    )

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        """Validate that either content or attachment_url is provided."""
        if not self.content and not self.attachment_url:
            raise ValueError("Either content or attachment_url must be provided")
        return self

    @computed_field
    @property
    def content_hash(self) -> str:
        """Calculate the content hash from the content."""
        import hashlib

        return hashlib.sha256(self.content.encode()).hexdigest()


class LegalDocumentSchema(LegalDocumentCreateSchema, TenantScopedEntitySchema):
    """Published legal document version."""


class LegalAcceptanceCreateSchema(BaseModel):
    """Record acceptance of a legal document."""

    document_id: str = Field(..., description="UID of the accepted LegalDocument.")
    workspace_id: str | None = Field(
        default=None,
        description="Required when accepting a workspace-scoped document.",
    )
    source: LegalAcceptanceSource = Field(
        default=LegalAcceptanceSource.LOGIN,
        description="Flow where acceptance was captured.",
    )


class LegalAcceptanceSchema(LegalAcceptanceCreateSchema, TenantUserEntitySchema):
    """Immutable audit record of a legal document acceptance."""

    subject_scope: LegalSubjectScope = Field(
        ..., description="Whether acceptance applies to a user or workspace."
    )
    document_type: LegalDocumentType = Field(
        ..., description="Denormalized document type for audit queries."
    )
    document_version: str = Field(
        ..., description="Denormalized document version for audit queries."
    )
    document_content_hash: str = Field(
        ..., description="Denormalized content hash at acceptance time."
    )
    accepted_at: datetime = Field(..., description="When the acceptance was recorded.")
    ip_address: str = Field(..., description="Client IP at acceptance time.")
    user_agent: str = Field(..., description="Client user agent at acceptance time.")


class LegalDocumentWithAcceptanceResponseSchema(LegalDocumentSchema):
    """Legal document with acceptance information."""

    acceptance: LegalAcceptanceSchema | None = Field(
        default=None, description="Acceptance for the document."
    )
