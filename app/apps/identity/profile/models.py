"""Profile models."""

from typing import Self

from fastapi_mongo_base.models import TenantUserEntity

from .schemas import ProfileSchema


class Profile(ProfileSchema, TenantUserEntity):
    """Profile model."""

    @classmethod
    async def get_by_user_id(cls, *, tenant_id: str, user_id: str) -> Self:
        """Get profile by user ID."""
        profile = await cls.find_one({"user_id": user_id, "tenant_id": tenant_id})
        if profile is None:
            profile = cls(tenant_id=tenant_id, user_id=user_id)
            await profile.save()
        await profile.get_identifiers()

        return profile

    async def get_identifiers(self) -> Self:
        """Get user identifiers."""
        from apps.identity.user.models import User

        user = await User.get_item(uid=self.user_id, tenant_id=self.tenant_id)
        identifiers = await user.get_identifiers(not_cached=True)
        self._identifiers = {
            identifier.type: identifier.identifier for identifier in identifiers
        }
        return self

    async def get_user_custom_claims(self) -> dict:
        """Get user custom claims."""
        from apps.identity.user.models import User

        user = await User.get_item(uid=self.user_id, tenant_id=self.tenant_id)
        return user.custom_claims
