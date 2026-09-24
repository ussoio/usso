"""KYC database models."""

from typing import Self

from fastapi_mongo_base.models import TenantUserEntity

from .schemas import KYCSchema, KYCStatus


class KYC(KYCSchema, TenantUserEntity):
    """KYC model."""

    @classmethod
    async def get_by_national_code(
        cls, national_code: str, tenant_id: str
    ) -> Self | None:
        """Get KYC by national code."""
        return await cls.find_one({
            "national_code": national_code,
            "tenant_id": tenant_id,
            "is_deleted": False,
            "status": KYCStatus.APPROVED,
        })

    @classmethod
    async def get_by_user_id(cls, user_id: str, tenant_id: str) -> Self | None:
        """Get KYC by user ID."""
        return await cls.find_one({
            "user_id": user_id,
            "tenant_id": tenant_id,
            "is_deleted": False,
            "status": KYCStatus.APPROVED,
        })
