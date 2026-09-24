"""
Tenant management API routes.

This module provides endpoints for managing tenants, including creation,
updates, and configuration retrieval.
"""

import logging

from fastapi import Request
from fastapi_mongo_base.routes import AbstractBaseRouter
from usso import UserData
from usso.integrations.fastapi import USSOAuthentication

from server.config import Settings
from server.exceptions import BadRequestError

from . import config, models, schemas, secrets, services

logger = logging.getLogger(__name__)


class TenantRouter(AbstractBaseRouter):
    """
    Router for tenant management endpoints.

    Extends AbstractBaseRouter to provide CRUD operations for tenants
    with additional configuration endpoint.
    """

    model = models.Tenant
    schema = schemas.TenantRetrieveSchema

    def config_routes(self, **kwargs: object) -> None:
        """Configure tenant routes including config endpoint."""
        self.router.add_api_route(
            "/config",
            self.get_config,
            methods=["GET"],
            status_code=200,
            response_model=config.PublicTenantConfig,
        )
        super().config_routes(**kwargs)

    def config_schemas(
        self, schema: schemas.TenantRetrieveSchema, **kwargs: object
    ) -> None:
        """Configure tenant schemas."""
        return super().config_schemas(schema, **kwargs)

    async def get_user(self, request: Request, **kwargs: object) -> UserData:
        """
        Get authenticated user from main tenant USSO.

        Args:
            request: The FastAPI request object.
            **kwargs: Additional keyword arguments.

        Returns:
            UserData instance from USSO authentication.

        Raises:
            ResourceError: If main tenant is not found.

        """
        main_tenant: models.Tenant = await models.Tenant.get_from_domain(
            Settings.root_url
        )
        if not main_tenant:
            raise BadRequestError(
                error_code="tenant_not_found",
                detail="Main tenant not found.",
                message={"en": "Main tenant not found.", "fa": "سامانه اصلی پیدا نشد."},
            )
        usso: USSOAuthentication = main_tenant.access_auth
        return usso(request)

    async def create_item(
        self,
        request: Request,
        data: schemas.TenantCreateSchema,
    ) -> models.Tenant:
        """
        Create a new tenant with generated secrets.

        Args:
            request: The FastAPI request object.
            data: Tenant creation schema data.

        Returns:
            Created Tenant instance, or None if creation fails.

        """
        user_id = await self.get_user_id(request=request)
        secret = secrets.TenantSecrets.generate_random_tenant_secrets(
            alg=data.algorithm
        )
        try:
            item = await super().create_item(
                request=request,
                data={
                    **data.model_dump(),
                    "secrets": secret,
                    "user_id": user_id,
                },
            )
        except Exception:
            logger.exception("Error creating tenant")
            return None
        else:
            return item

    async def update_item(
        self, request: Request, uid: str, data: schemas.TenantUpdateSchema
    ) -> models.Tenant:
        """
        Update an existing tenant.

        Args:
            request: The FastAPI request object.
            uid: Unique identifier of the tenant to update.
            data: Tenant update schema data.

        Returns:
            Updated Tenant instance.

        """
        payload = data.model_dump(exclude_none=True)
        if payload.get("config") is not None:
            user_id = await self.get_user_id(request)
            item = await self.get_item(uid=uid, user_id=user_id)
            current = item.config.model_dump(mode="json")
            merged = schemas.deep_merge_dicts(current, payload["config"])
            payload["config"] = config.TenantConfig.model_validate(merged)
        return await super().update_item(request, uid, payload)

    async def get_config(self, request: Request) -> config.PublicTenantConfig:
        """
        Get public configuration for the main tenant.

        Resolves tenant by request hostname first, then falls back to
        Settings.root_url, and finally returns the first available tenant.

        Args:
            request: The FastAPI request object.

        Returns:
            PublicTenantConfig instance with tenant configuration.

        Raises:
            ResourceError: If no tenant is found.

        """
        tenant: models.Tenant | None = None

        # 1. Try request hostname
        hostname = request.url.hostname
        if hostname:
            tenant = await models.Tenant.get_from_domain(hostname)

        # 2. Fallback: Settings.root_url
        if not tenant:
            tenant = await models.Tenant.get_from_domain(Settings.root_url)

        # 3. Fallback: first available tenant
        if not tenant:
            tenant = await models.Tenant.find_one()

        if not tenant:
            raise BadRequestError(
                error_code="tenant_not_found",
                detail="Main tenant not found.",
                message={"en": "Main tenant not found.", "fa": "سامانه اصلی پیدا نشد."},
            )
        telegram_oauth = tenant.secrets.oauth_secrets.get("telegram")
        return config.PublicTenantConfig.model_validate(
            tenant.config.model_dump()
            | {
                "integration": services.list_public_integration_providers(tenant),
                "name": tenant.name,
                "telegram_client_id": (
                    telegram_oauth.client_id if telegram_oauth else None
                ),
            }
        )


router = TenantRouter().router
