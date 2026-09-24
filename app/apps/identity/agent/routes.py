"""Agent routes."""

import logging

from fastapi import Depends, Request

from server.exceptions import BadRequestError, UnauthorizedError
from server.rate_limiter import get_rate_limiter
from utils.usso_routes import AbstractTenantUSSORouter

from ..auth.schemas import LoginResponse
from ..auth.services import require_secure_token
from . import models, schemas, services

logger = logging.getLogger(__name__)


class AgentRouter(AbstractTenantUSSORouter):
    """Agent router."""

    model = models.Agent
    schema = schemas.AgentResponseSchema

    def config_schemas(self, schema: type, **kwargs: object) -> None:
        """Configure schemas."""
        super().config_schemas(schema, **kwargs)
        self.create_response_schema = schemas.AgentCreateResponse

    def config_routes(self, **kwargs: object) -> None:
        """Configure routes."""
        super().config_routes(**kwargs)
        self.router.add_api_route(
            "/auth",
            self.agent_auth,
            methods=["POST"],
            dependencies=[Depends(get_rate_limiter("/agents/auth"))],
            response_model=LoginResponse,
            status_code=200,
        )
        self.router.add_api_route(
            "/scopes",
            self.agent_scopes,
            methods=["POST"],
            dependencies=[Depends(get_rate_limiter("/agents/auth"))],
            response_model=schemas.AgentResponseSchema,
            status_code=200,
        )

    async def create_item(
        self, request: Request, data: schemas.AgentCreateSchema
    ) -> schemas.AgentCreateResponse:
        """Create an agent."""
        tenant = await self.get_tenant(request)
        caller = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=caller.uid)
        if not tenant.config.agents.enabled:
            raise BadRequestError(
                error_code="agents_not_enabled",
                detail="Agents are not enabled for this tenant.",
                message={
                    "en": "Agents are not enabled for this tenant.",
                    "fa": "قابلیت تعریف عامل در این سامانه فعال نیست.",
                },
            )

        from ..user.models import User

        caller_user = await User.get_item(uid=caller.uid, tenant_id=tenant.uid)
        if caller_user is None:
            raise UnauthorizedError(
                error_code="user_not_found",
                detail="User not found",
                message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
            )

        return await services.generate_agent(data, tenant, caller, caller_user)

    async def update_item(
        self, request: Request, uid: str, data: schemas.AgentUpdateSchema
    ) -> schemas.AgentResponseSchema:
        """Update an agent (scope changes require secure-token + ceiling)."""
        from apps.identity.service_account import (
            assert_scopes_subset,
            resolve_scope_ceiling,
        )

        from ..user.models import User

        tenant = await self.get_tenant(request)
        caller = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=caller.uid)

        item = await self.get_item(uid=uid, user_id=None, tenant_id=caller.tenant_id)
        data_dict = data.model_dump(exclude_none=True)
        if "scopes" in data_dict:
            caller_user = await User.get_item(uid=caller.uid, tenant_id=tenant.uid)
            if caller_user is None:
                raise UnauthorizedError(
                    error_code="user_not_found",
                    detail="User not found",
                    message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
                )
            ceiling = await resolve_scope_ceiling(
                caller_user=caller_user,
                user_id=item.user_id,
                workspace_id=item.workspace_id,
            )
            assert_scopes_subset(requested=data_dict["scopes"], ceiling=ceiling)

        return await super().update_item(request, uid, data_dict)

    async def delete_item(
        self, request: Request, uid: str
    ) -> schemas.AgentResponseSchema:
        """Delete an agent after recent-authentication verification."""
        tenant = await self.get_tenant(request)
        caller = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=caller.uid)
        return await super().delete_item(request, uid)

    async def agent_auth(self, request: Request) -> LoginResponse:
        """Authenticate an agent."""
        tenant = await self.get_tenant(request)

        logger.info("Agent auth request: %s", request.headers)

        jwt = request.headers.get("Authorization")
        if not jwt or not jwt.startswith("Bearer "):
            raise UnauthorizedError(
                error_code="jwt_required",
                detail="JWT is required.",
                message={"en": "JWT is required.", "fa": "توکن دسترسی الزامی است."},
            )
        jwt = jwt.split(" ")[1]
        agent, payload = await services.agent_auth(jwt, tenant_id=tenant.uid)

        auth_response = services.create_agent_response(
            agent=agent,
            tenant=tenant,
            scopes=payload.scopes,
            aud=payload.aud,
        )

        return auth_response

    async def agent_scopes(self, request: Request) -> schemas.AgentResponseSchema:
        """Get the scopes of an agent."""
        tenant = await self.get_tenant(request)
        jwt = request.headers.get("Authorization")
        if not jwt or not jwt.startswith("Bearer "):
            raise UnauthorizedError(
                error_code="jwt_required",
                detail="JWT is required.",
                message={"en": "JWT is required.", "fa": "توکن دسترسی الزامی است."},
            )
        jwt = jwt.split(" ")[1]
        agent, _ = await services.agent_auth(jwt, tenant_id=tenant.uid)

        return schemas.AgentResponseSchema.model_validate(agent)


router = AgentRouter().router
