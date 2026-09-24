"""API key models."""

from typing import ClassVar

from fastapi_mongo_base.models import ASCENDING, IndexModel, TenantScopedEntity
from usso import authorization

from .schemas import APIKeySchema


class APIKey(APIKeySchema, TenantScopedEntity):
    """API key model (service account keyed by uid)."""

    class Settings:
        """API key settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantScopedEntity.Settings.indexes,
            IndexModel([
                ("tenant_id", ASCENDING),
                ("user_id", ASCENDING),
                ("uid", ASCENDING),
                ("is_deleted", ASCENDING),
            ]),
            IndexModel([
                ("tenant_id", ASCENDING),
                ("workspace_id", ASCENDING),
                ("uid", ASCENDING),
                ("is_deleted", ASCENDING),
            ]),
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("api_key_pattern", ASCENDING),
                ],
            ),
        ]

    @classmethod
    async def cap_user_api_keys_scopes(
        cls,
        *,
        user_id: str,
        tenant_id: str,
        user_scopes: list[str],
        workspace_id: str | None = None,
    ) -> int:
        """
        Cap API key scopes to user's current scopes (subset semantics).

        Only keys with the given user_id (+ optional workspace_id) are updated.
        """
        query: dict = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "is_deleted": False,
            "workspace_id": workspace_id,
        }
        keys = await cls.find(query).to_list()
        updated = 0
        for key in keys:
            capped = [
                s
                for s in (key.scopes or [])
                if authorization.has_subset_scope(
                    subset_scope=s, user_scopes=user_scopes
                )
            ]
            if capped != (key.scopes or []):
                key.scopes = capped
                await key.save()
                from .services import invalidate_api_key_cache

                await invalidate_api_key_cache(uid=key.uid)
                updated += 1
        return updated
