"""Referral models."""

from typing import ClassVar, Self

from fastapi_mongo_base.models import (
    ASCENDING,
    IndexModel,
    TenantUserEntity,
)

from .schemas import ReferralCodeSchema


class ReferralCode(ReferralCodeSchema, TenantUserEntity):
    """Referral code model."""

    class Settings:
        """Referral code settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel(
                [("tenant_id", ASCENDING), ("code", ASCENDING)],
                unique=True,
            ),
        ]

    @classmethod
    async def get_by_code(cls, code: str, tenant_id: str) -> Self:
        """Get referral code by code and tenant ID."""
        return await cls.find_one({"code": code, "tenant_id": tenant_id})
