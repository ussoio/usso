"""Session routes."""

from datetime import datetime

from fastapi import Query, Request
from fastapi_mongo_base.schemas import PaginatedResponse

from server.config import Settings
from utils.usso_routes import AbstractTenantUSSORouter

from . import models, schemas


class SessionRouter(AbstractTenantUSSORouter):
    """Session router."""

    model = models.AuthSession
    schema = schemas.AuthSessionSchema
    resource = "session"

    def __init__(self) -> None:
        """Initialize session router."""
        super().__init__(prefix="/sessions")

    def config_routes(self, **kwargs: object) -> None:
        """Expose read/revoke only; sessions may be created only by auth flows."""
        super().config_routes(
            create_route=False,
            update_route=False,
            **kwargs,
        )

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        created_at_from: datetime | None = None,
        created_at_to: datetime | None = None,
        user_id: str | None = None,
    ) -> PaginatedResponse[schemas.AuthSessionSchema]:
        """List sessions."""
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            created_at_from=created_at_from,
            created_at_to=created_at_to,
            user_id=user_id,
        )


router = SessionRouter().router
