"""
USSO route utilities and custom exceptions.

This module provides custom router classes and exceptions for USSO
authentication and tenant management integration.
"""

from fastapi import Request
from fastapi_mongo_base.utils import usso_routes
from usso import UserData
from usso.integrations.fastapi import USSOAuthentication

from apps.tenant.models import Tenant
from apps.tenant.services import get_request_tenant

__all__ = ["AbstractTenantUSSORouter"]


class AbstractTenantUSSORouter(usso_routes.AbstractTenantUSSORouter):
    """
    Abstract router for USSO-authenticated routes with tenant support.

    Extends the base USSO router to integrate with tenant management,
    automatically resolving the tenant from the request and providing
    user authentication via USSO.
    """

    async def get_tenant(self, request: Request, **kwargs: object) -> Tenant:
        """
        Get the tenant associated with the request.

        Args:
            request: The FastAPI request object.
            **kwargs: Additional keyword arguments.

        Returns:
            The Tenant instance associated with the request.

        """
        tenant = await get_request_tenant(request)
        return tenant

    async def get_user(self, request: Request, **kwargs: object) -> UserData | None:
        """
        Get the authenticated user data from USSO.

        Resolves the tenant first, then uses the tenant's USSO authentication
        to get the current user.

        Args:
            request: The FastAPI request object.
            **kwargs: Additional keyword arguments.

        Returns:
            UserData instance if authenticated, None otherwise.

        """
        tenant = await self.get_tenant(request=request, **kwargs)
        usso: USSOAuthentication = tenant.access_auth
        return await usso.usso_access_security_async(request)
