"""
Session schemas for authentication and identity management.

Defines the AuthSession model, which represents a user or
service session in the system. This model tracks authentication flow,
session metadata, and expiration logic for multi-tenant environments.
"""

from datetime import datetime, timedelta
from enum import StrEnum

from fastapi_mongo_base.schemas import TenantScopedEntitySchema, TenantUserEntitySchema
from fastapi_mongo_base.utils import timezone
from pydantic import BaseModel, ConfigDict, Field

MAX_BROWSER_ACCOUNTS = 10


class SessionType(StrEnum):
    """
    Types of authentication sessions in the system.

    Authentication sessions are categorized based on how they were created
    and their intended usage pattern.
    """

    # Temporary sessions for multi-step authentication flows
    TEMPORARY = "temporary"

    # Standard user authentication sessions
    REGULAR_LOGIN = "regular_login"  # Full user login
    ACCOUNT_RECOVERY = "account_recovery"  # Account recovery flow
    CREDENTIAL_RECOVERY = "credential_recovery"  # Credential recovery
    IMPERSONATION = "impersonation"  # Impersonation flow

    # Programmatic authentication sessions
    API_KEY = "api_key"
    OAUTH_CLIENT = "oauth_client"  # OAuth client credentials
    OAUTH_SESSION = "oauth_session"  # OAuth session
    SERVICE_ACCOUNT = "service_account"

    # Single-use sessions
    ONE_TIME_ACCESS = "one_time_access"  # Single-use access


class AuthSessionSchema(TenantUserEntitySchema):
    """
    Represents an authentication session for a user or service.

    Stores session metadata, authentication flow used, and expiration logic.
    Used for tracking active sessions, auditing, and enforcing security policies.
    """

    workspace_id: str | None = Field(
        default=None,
        description="Workspace ID associated with the session",
    )
    assumed_from_workspace_id: str | None = Field(
        default=None,
        description=(
            "Previous workspace_id when a system admin entered another "
            "workspace without membership"
        ),
    )
    aud: str | None = Field(
        default=None,
        description="Target audience for access tokens generated from this session",
    )
    roles: list[str] | None = Field(
        default=None,
        description="Roles granted to the session",
    )
    scopes: list[str] | None = Field(
        default=None,
        description="Scopes granted to the session",
    )
    amr: list[str] = Field(
        default_factory=list,
        description="Authentication methods used to create the session",
    )
    last_used_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the last session refresh (for sliding expiration)",
    )
    max_age_minutes: int | None = Field(
        default=None,
        description="Maximum session lifetime in minutes. "
        "If None, session does not expire automatically.",
    )
    user_agent: str = Field(
        ...,
        description="User agent string of the client initiating the session",
    )
    ip: str = Field(..., description="IP address from which the session was initiated")
    location: str | None = Field(
        default=None,
        description="Geographical location (if available) of the session origin",
    )
    claims: dict | None = Field(
        default=None,
        description="Custom claims associated with the session",
    )
    session_type: SessionType = SessionType.REGULAR_LOGIN

    @property
    def expire_at(self) -> datetime | None:
        """
        The expiration datetime for the session.

        Returns None if the session does not expire.
        """
        if self.max_age_minutes is None:
            return None
        return self.created_at.replace(tzinfo=timezone.tz) + timedelta(
            minutes=self.max_age_minutes
        )

    @property
    def is_expired(self) -> bool:
        """True if the session is expired, False otherwise."""
        expire_at = self.expire_at
        if expire_at is None:
            return False
        return expire_at < datetime.now(timezone.tz)

    def update_scopes(self, new_scopes: list[str]) -> list[str]:
        """Update the scopes for the session."""
        self.scopes = new_scopes
        return self.scopes


class BrowserAccountEntry(BaseModel):
    """One refreshable session linked to a browser account set."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(..., min_length=1, max_length=128)
    session_id: str = Field(..., min_length=1, max_length=128)
    session_type: SessionType = SessionType.REGULAR_LOGIN
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.tz))
    last_used_at: datetime = Field(default_factory=lambda: datetime.now(timezone.tz))


class BrowserAccountSetSchema(TenantScopedEntitySchema):
    """Server-side account set addressed by an opaque browser credential."""

    credential_digest: str = Field(..., min_length=64, max_length=64)
    entries: list[BrowserAccountEntry] = Field(
        default_factory=list,
        max_length=MAX_BROWSER_ACCOUNTS,
    )
    active_session_id: str | None = Field(default=None, max_length=128)
    expires_at: datetime
