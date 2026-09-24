"""Profile routes."""

import uuid

from fastapi import Request

from utils import usso_routes

from .models import Profile
from .schemas import (
    ProfileCreateSchema,
    ProfileResponseSchema,
    ProfileUpdateSchema,
)


class ProfileRouter(usso_routes.AbstractTenantUSSORouter):
    """Profile router."""

    model = Profile
    schema = ProfileResponseSchema

    unique_per_user = True
    create_mine_if_not_found = True

    def config_routes(self, **kwargs: object) -> None:
        """Configure routes."""
        super().config_routes(update_route=False, mine_route=True, **kwargs)
        self.router.add_api_route(
            "/mine",
            self.update_mine_items,
            methods=["PATCH"],
            response_model=self.retrieve_response_schema,
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid:str}",
            self.update_item,
            methods=["PATCH"],
            response_model=self.update_response_schema,
            status_code=200,
        )

    async def create_item(
        self, request: Request, profile: ProfileCreateSchema
    ) -> ProfileResponseSchema:
        """Create a profile."""
        return await super().create_item(request, profile.model_dump())

    async def update_item(
        self, request: Request, uid: uuid.UUID, profile: ProfileUpdateSchema
    ) -> ProfileResponseSchema:
        """Update a profile."""
        return await super().update_item(
            request, uid, profile.model_dump(exclude_unset=True)
        )

    async def mine_items(self, request: Request) -> ProfileResponseSchema:
        """Get current user's profile."""
        return await super().mine_items(request)

    async def update_mine_items(
        self, request: Request, profile: ProfileUpdateSchema
    ) -> ProfileResponseSchema:
        """Update current user's profile."""
        user = await self.get_user(request)
        return await self.update_item(request, user.uid, profile)


router = ProfileRouter().router
