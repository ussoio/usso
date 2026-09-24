"""Beanie model for per-tenant scope catalog entries."""

from typing import ClassVar

from fastapi_mongo_base.models import ASCENDING, IndexModel, TenantScopedEntity

from .schemas import ScopeCatalogSchema


class ScopeCatalog(ScopeCatalogSchema, TenantScopedEntity):
    """One selectable scope for a tenant, keyed by service + scope string."""

    class Settings:
        """Mongo indexes for catalog lookups and uniqueness."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantScopedEntity.Settings.indexes,
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("service", ASCENDING),
                    ("scope", ASCENDING),
                ],
                unique=True,
                partialFilterExpression={"is_deleted": False},
            ),
            IndexModel([
                ("tenant_id", ASCENDING),
                ("service", ASCENDING),
                ("source", ASCENDING),
                ("is_deleted", ASCENDING),
            ]),
        ]
