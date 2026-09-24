"""Agent (Service Account) models."""

from typing import ClassVar, Self

from fastapi_mongo_base.models import ASCENDING, IndexModel, TenantScopedEntity
from usso import authorization

from .schemas import AgentSchema


class Agent(AgentSchema, TenantScopedEntity):
    """Agent (Service Account) model."""

    class Settings:
        """Agent settings."""

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
                [("tenant_id", ASCENDING), ("kid", ASCENDING)],
                unique=True,
                partialFilterExpression={
                    "is_deleted": False,
                    "kid": {"$type": "string"},
                },
            ),
        ]

    @classmethod
    async def get_by_kid(cls, *, kid: str, tenant_id: str) -> Self | None:
        """Look up a live agent by public-key thumbprint within a tenant."""
        return await cls.find_one({
            "kid": kid,
            "tenant_id": tenant_id,
            "is_deleted": False,
        })

    @classmethod
    async def cap_user_agents_scopes(
        cls,
        *,
        user_id: str,
        tenant_id: str,
        user_scopes: list[str],
        workspace_id: str | None = None,
    ) -> int:
        """
        Cap agent scopes to user's current scopes (subset semantics).

        Only agents with the given user_id (+ optional workspace_id) are updated.
        """
        query = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "is_deleted": False,
            "workspace_id": workspace_id,
        }
        agents = await cls.find(query).to_list()
        updated = 0
        for agent in agents:
            capped = [
                s
                for s in (agent.scopes or [])
                if authorization.has_subset_scope(
                    subset_scope=s, user_scopes=user_scopes
                )
            ]
            if capped != (agent.scopes or []):
                agent.scopes = capped
                await agent.save()
                updated += 1
        return updated
