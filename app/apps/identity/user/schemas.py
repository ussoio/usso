"""
User schemas for Pydantic models.

This module defines Pydantic schemas for users, user identifiers,
credentials, and related data structures.
"""

import logging
from datetime import date, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from fastapi_mongo_base.schemas import (
    TenantScopedEntitySchema,
    TenantUserEntitySchema,
)
from pydantic import BaseModel, Field, ValidationInfo, field_validator

from ..auth.enums import AuthIdentifier, AuthSecret, AuthStep

logger = logging.getLogger(__name__)


class ActivationStatus(StrEnum):
    """User activation status enumeration."""

    ACTIVE = "active"
    DEACTIVE = "deactive"
    PENDING = "pending"
    BANNED = "banned"


class UserIdentifierSchema(TenantUserEntitySchema):
    """
    Schema for user identifiers (email, phone, username, etc.).

    Attributes:
        type: Type of identifier (email, phone, username, etc.).
        identifier: The identifier value.
        verified_at: Timestamp when identifier was verified.
        is_primary: Whether this is the primary identifier.
        is_active: Whether the identifier is currently active.

    """

    type: AuthIdentifier
    identifier: str
    verified_at: datetime | None = Field(
        default=None,
        description="The date and time the identifier was verified, if verified",
    )
    is_primary: bool = False
    is_active: bool = True
    searchable: bool = Field(
        default=True,
        description="Whether this identifier may appear in user search results",
    )

    @property
    def redis_key(self) -> str:
        """
        Redis key for this identifier.

        Returns:
            Redis key string for caching identifier data.

        """
        return f"user_identifier:{self.tenant_id}:{self.type}:{self.identifier}"

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, v: str, info: ValidationInfo) -> str:
        """
        Validate identifier based on its type.

        Args:
            v: Identifier value to validate.
            info: Validation context with data.

        Returns:
            Canonicalized identifier string.

        Raises:
            ValueError: If identifier is invalid for its type.

        """
        if info.data["type"] != "phone":
            return v

        validator = info.data["type"].get_identifier_validator()
        is_valid, error, canonical_identifier = validator(v)
        if not is_valid:
            logger.error("Invalid identifier: %s, error: %s", v, error)
            raise ValueError(error)
        return canonical_identifier


class CredentialSchema(TenantUserEntitySchema):
    """
    Schema for user authentication credentials.

    Attributes:
        method: Authentication method (password, TOTP, etc.).
        secret: Encrypted secret value.
        last_used_at: Timestamp of last credential use.
        is_active: Whether the credential is currently active.
        expires_at: Expiration timestamp if applicable.

    """

    method: AuthSecret
    secret: str
    last_used_at: datetime | None = None
    is_active: bool = True
    expires_at: datetime | None = None


class CredentialResponseSchema(CredentialSchema):
    """Response schema for credentials - excludes sensitive data."""

    secret: ClassVar[None] = None


class CredentialCreateSchema(BaseModel):
    """Schema for creating new credentials."""

    method: AuthSecret
    secret: str
    expires_at: datetime | None = None


class TOTPCreateSchema(CredentialCreateSchema):
    """Schema for creating new credentials."""

    method: Literal[AuthSecret.TOTP] = AuthSecret.TOTP
    secret: str
    expires_at: datetime | None = None


class CredentialUpdateSchema(BaseModel):
    """Schema for updating credentials."""

    secret: str | None = None
    is_active: bool | None = None
    expires_at: datetime | None = None


class UserIdentifierCreateSchema(BaseModel):
    """Schema for creating new user identifiers."""

    type: AuthIdentifier
    identifier: str
    is_primary: bool = False


class UserIdentifierUpdateSchema(BaseModel):
    """Schema for updating user identifiers."""

    identifier: str | None = None
    is_primary: bool | None = None
    is_active: bool | None = None
    searchable: bool | None = None


class VerificationRequestSchema(BaseModel):
    """Schema for verification requests."""

    code: str = Field(..., description="Verification code")


class PasswordResetRequestSchema(BaseModel):
    """Schema for password reset via email."""

    identifier: str = Field(..., description="Email address for password reset")
    identifier_type: AuthIdentifier = AuthIdentifier.EMAIL


class UserSchema(TenantScopedEntitySchema):
    """User schema."""

    name: str | None = None
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] | None = None
    workspace_roles: dict[str, list[str]] = Field(default_factory=dict)

    workspace_ids: list[str] = Field(default_factory=list)
    is_active: bool = Field(
        default=False,
        description=(
            "Control activation by user. "
            "Based on tenant.config.registration.approval_mode"
        ),
    )
    is_limited: bool = Field(default=False, description="Control by tenant admin.")
    activation_status: ActivationStatus = ActivationStatus.ACTIVE
    searchable: bool = Field(
        default=True,
        description="Whether this user may appear in workspace user search",
    )

    avatar_url: str | None = None

    mfa_enabled: bool = False
    mfa_steps: list[AuthStep] | None = None
    linked_accounts: list[str] = Field(
        default_factory=list, description="List of uid of linked accounts."
    )

    custom_claims: dict = Field(default_factory=dict)

    history: list[dict[str, object]] = Field(default_factory=list)

    @property
    def user_id(self) -> str:
        """
        User ID.

        Returns:
            User unique identifier.

        """
        return self.uid

    @property
    def user_name(self) -> str:
        """
        User name.

        Returns:
            User's display name.

        """
        return self.name


class UserWorkspaceRef(BaseModel):
    """Workspace summary for user directory chips (response-only)."""

    uid: str
    name: str | None = None
    organization_code: str | None = None
    type: str | None = None


class UserResponse(TenantScopedEntitySchema):
    """
    Response schema for user data.

    Attributes:
        name: User's display name.
        roles: List of role names assigned to the user.

    """

    name: str | None = None
    roles: list[str]
    scopes: list[str] | None = None
    workspace_roles: dict[str, list[str]] = Field(default_factory=dict)
    workspace_ids: list[str] = Field(default_factory=list)
    is_active: bool = False
    is_limited: bool = False
    activation_status: ActivationStatus = ActivationStatus.ACTIVE
    searchable: bool = True
    avatar_url: str | None = None
    custom_claims: dict = Field(default_factory=dict)
    history: list[dict[str, object]] = Field(default_factory=list)

    identifiers: list[UserIdentifierSchema] = Field(default_factory=list)
    credential_methods: list[str] = Field(default_factory=list)
    workspaces: list[UserWorkspaceRef] = Field(default_factory=list)


class UserCreateSchema(BaseModel):
    """
    Schema for creating a new user.

    Attributes:
        name: User's display name.
        identifier_type: Type of identifier to use for the user.

    """

    name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    national_id: str | None = None
    # Persisted on the KYC record via upsert_admin_kyc (not on User).
    birth_date: date | None = None
    identifier_type: AuthIdentifier = AuthIdentifier.EMAIL
    identifier: str = Field(..., description="Identifier address")
    referral_code: str | None = Field(
        default=None,
        description="Optional referral/invite code to consume on creation",
    )

    roles: list[str] = Field(default_factory=list)

    meta_data: dict | None = Field(
        default=None, description="Additional metadata for the entity"
    )


class UserUpdateSchema(BaseModel):
    """
    Schema for updating user information.

    Attributes:
        name: Updated display name.
        roles: Updated list of role names.

    """

    name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    # Persisted on the KYC record via upsert_admin_kyc (not on User).
    birth_date: date | None = None
    roles: list[str] | None = None
    scopes: list[str] | None = None
    workspace_roles: dict[str, list[str]] | None = None
    workspace_ids: list[str] | None = None
    is_active: bool | None = None
    is_limited: bool | None = None
    activation_status: ActivationStatus | None = None
    searchable: bool | None = None
    avatar_url: str | None = None
    custom_claims: dict | None = None

    meta_data: dict | None = Field(
        default=None, description="Additional metadata for the entity"
    )


class ImpersonationMode(StrEnum):
    """Impersonation privilege mode."""

    READONLY = "readonly"
    FULL = "full"


class ImpersonateRequest(BaseModel):
    """Request body for admin impersonation."""

    mode: ImpersonationMode = ImpersonationMode.FULL


class ImpersonateOTPRequest(BaseModel):
    """Request body to send OTP for consented impersonation."""

    mode: ImpersonationMode = ImpersonationMode.FULL
    identifier_type: AuthIdentifier | None = Field(
        default=None,
        description="Preferred destination identifier type (phone/email).",
    )


class ImpersonateOTPVerifyRequest(BaseModel):
    """Request body to verify OTP and start impersonation."""

    mode: ImpersonationMode = ImpersonationMode.FULL
    otp: str = Field(..., description="One-time password sent to target user")
