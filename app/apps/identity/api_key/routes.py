"""API key routes."""

from fastapi import Depends, Request
from fastapi_mongo_base.schemas import PaginatedResponse
from usso import UserData

from apps.identity.service_account import (
    assert_scopes_subset,
    authorize_service_account_create,
    resolve_create_binding,
    resolve_scope_ceiling,
)
from server.rate_limiter import get_rate_limiter
from utils.hasher import PasswordHasherService
from utils.usso_routes import AbstractTenantUSSORouter

from ..auth.services import require_secure_token
from ..user.models import User
from . import models, schemas, services


class APIKeyRouter(AbstractTenantUSSORouter):
    """API key router."""

    model = models.APIKey
    schema = schemas.APIKeyResponseSchema
    # Listing/auth still keyed by user when present; create sets binding explicitly.
    owner_attr = "user_id"

    def config_schemas(
        self, schema: schemas.APIKeyResponseSchema, **kwargs: object
    ) -> None:
        """Configure schemas."""
        super().config_schemas(schema, **kwargs)
        self.create_response_schema = schemas.APIKeyCreateResponseSchema
        self.verify_response_schema = UserData

    def config_routes(self, **kwargs: object) -> None:
        """Configure routes."""
        super().config_routes(update_route=False, **kwargs)
        self.router.add_api_route(
            "/verify",
            self.verify,
            methods=["POST"],
            dependencies=[Depends(get_rate_limiter("/apikeys/verify"))],
            response_model=self.verify_response_schema,
            status_code=200,
        )

    def _to_response(self, item: models.APIKey) -> schemas.APIKeyResponseSchema:
        data = item.model_dump()
        data["client_id"] = item.uid
        return self.schema.model_validate(data)

    async def _list_items(
        self,
        request: Request,
        offset: int = 0,
        limit: int = 10,
        **kwargs: object,
    ) -> PaginatedResponse[schemas.APIKeyResponseSchema]:
        result = await super()._list_items(
            request, offset=offset, limit=limit, **kwargs
        )
        result.items = [
            item.model_copy(update={"client_id": item.uid}) for item in result.items
        ]
        return result

    async def create_item(
        self, request: Request, data: schemas.APIKeyCreateSchema
    ) -> schemas.APIKeyCreateResponseSchema:
        """Create an API key service account."""
        tenant = await self.get_tenant(request)
        caller = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=caller.uid)
        caller_user = await User.get_item(uid=caller.uid, tenant_id=tenant.uid)
        if caller_user is None:
            from server.exceptions import UnauthorizedError

            raise UnauthorizedError(
                error_code="user_not_found",
                detail="User not found",
                message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
            )

        user_id, workspace_id = resolve_create_binding(
            caller=caller,
            user_id=data.user_id,
            workspace_id=data.workspace_id,
        )
        authorize_service_account_create(
            caller=caller, user_id=user_id, workspace_id=workspace_id
        )

        ceiling = await resolve_scope_ceiling(
            caller_user=caller_user,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        assert_scopes_subset(requested=data.scopes, ceiling=ceiling)

        key_data = services.generate_api_key()
        api_key_plaintext = key_data.pop("api_key")
        key_data.pop("secret_length", None)
        client_secret = services.generate_client_secret()
        hashed_client_secret = PasswordHasherService().hash_password(client_secret)

        item = await models.APIKey(
            tenant_id=tenant.uid,
            user_id=user_id,
            workspace_id=workspace_id,
            created_by=caller.uid,
            name=data.name,
            description=data.description,
            scopes=data.scopes,
            ip_whitelist=data.ip_whitelist,
            rate_limit=data.rate_limit,
            expires_at=data.expires_at,
            hashed_client_secret=hashed_client_secret,
            **key_data,
        ).save()

        return self.create_response_schema.model_validate({
            **item.model_dump(),
            "client_id": item.uid,
            "api_key": api_key_plaintext,
            "client_secret": client_secret,
        })

    async def delete_item(
        self, request: Request, uid: str
    ) -> schemas.APIKeyResponseSchema:
        """Delete an API key and invalidate its verification cache."""
        tenant = await self.get_tenant(request)
        caller = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=caller.uid)
        item = await super().delete_item(request, uid)
        await services.invalidate_api_key_cache(uid=uid)
        return item

    async def verify(
        self, request: Request, data: schemas.APIKeyVerifySchema
    ) -> UserData:
        """Verify an API key."""
        from utils.net import get_client_ip
        from utils.request_context import client_ip_var, user_agent_var

        client_ip_var.set(get_client_ip(request))
        user_agent_var.set(request.headers.get("user-agent"))
        tenant = await self.get_tenant(request)
        return await services.get_api_key_data(data.api_key, tenant_id=tenant.uid)


api_key_router = APIKeyRouter()
router = api_key_router.router
