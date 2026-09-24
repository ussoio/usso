"""Referral routes."""

from datetime import datetime

from fastapi import Query, Request
from fastapi_mongo_base.audit.context import audit_actor_scope
from fastapi_mongo_base.schemas import PaginatedResponse

from server.config import Settings
from utils.usso_routes import AbstractTenantUSSORouter

from . import models, schemas


class ReferralCodeRouter(AbstractTenantUSSORouter):
    """Referral code router."""

    model = models.ReferralCode
    schema = schemas.ReferralCodeSchema

    def __init__(self) -> None:
        """Initialize referral code router."""
        super().__init__(prefix="/referrals")

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        created_at_from: datetime | None = None,
        created_at_to: datetime | None = None,
        user_id: str | None = None,
    ) -> PaginatedResponse[schemas.ReferralCodeSchema]:
        """List referral codes."""
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            created_at_from=created_at_from,
            created_at_to=created_at_to,
            user_id=user_id,
        )

    async def create_item(
        self,
        request: Request,
        data: schemas.ReferralCodeCreateSchema,
    ) -> models.ReferralCode:
        """Create a referral; on-behalf creation requires an explicit scope."""
        user = await self.get_user(request)
        payload = data.model_dump(exclude_none=True)
        requested_owner = payload.pop("user_id", None)
        owner_id = requested_owner or self._owner_id_for_create(user)
        await self.authorize(
            action="create",
            user=user,
            filter_data={self.owner_attr: owner_id},
        )
        with audit_actor_scope(user):
            return await self.model.create_item({
                **payload,
                self.owner_attr: owner_id,
                "tenant_id": user.tenant_id,
                "usage_count": 0,
                "is_active": True,
            })


router = ReferralCodeRouter().router
