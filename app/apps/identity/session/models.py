"""Session models."""

from datetime import datetime
from typing import ClassVar

from fastapi_mongo_base.models import (
    ASCENDING,
    IndexModel,
    TenantScopedEntity,
    TenantUserEntity,
)
from fastapi_mongo_base.utils import timezone

from .schemas import AuthSessionSchema, BrowserAccountSetSchema


class AuthSession(AuthSessionSchema, TenantUserEntity):
    """Authentication session model."""

    class Settings:
        """Auth session settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel([("jti", ASCENDING)]),
        ]

    @classmethod
    async def revoke_user_sessions(cls, *, tenant_id: str, user_id: str) -> int:
        """Revoke every refreshable session after a credential reset."""
        result = await cls.get_pymongo_collection().update_many(
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "is_deleted": False,
            },
            {
                "$set": {
                    "is_deleted": True,
                    "updated_at": datetime.now(timezone.tz),
                }
            },
        )
        return result.modified_count

    @classmethod
    async def update_user_sessions_permissions(
        cls,
        *,
        user_id: str,
        tenant_id: str,
        new_scopes: list[str] | None = None,
        new_roles: list[str] | None = None,
        workspace_id: str | None = None,
    ) -> int:
        """
        Update permissions for all active sessions of a user.

        This method provides real-time session updates when user permissions change.

        Args:
            user_id: The user ID whose sessions should be updated
            tenant_id: The tenant ID
            new_scopes: New scopes to set (optional)
            new_roles: New roles to set (optional)
            workspace_id: Specific workspace to update (optional, updates all if None)

        Returns:
            Number of sessions updated

        """
        # Build query filter (only sessions for this workspace; None = global sessions)
        query_filter = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "is_deleted": False,
            "workspace_id": workspace_id,
        }

        # Build update data
        update_data = {"updated_at": datetime.now(timezone.tz)}

        if new_scopes is not None:
            update_data["scopes"] = new_scopes

        if new_roles is not None:
            update_data["roles"] = new_roles

        # Note: roles are typically stored in User model, not session
        # But if needed for caching, we can update them here too

        # Perform bulk update
        result = await cls.find(query_filter).update_many({"$set": update_data})

        return result.modified_count if result else 0


class BrowserAccountSet(BrowserAccountSetSchema, TenantScopedEntity):
    """A tenant-bound set of accounts available in one browser."""

    class Settings:
        """Browser account-set storage settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantScopedEntity.Settings.indexes,
            IndexModel(
                [("tenant_id", ASCENDING), ("credential_digest", ASCENDING)],
                unique=True,
            ),
            IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0),
        ]
