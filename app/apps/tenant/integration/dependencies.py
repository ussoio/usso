"""Dependencies for OAuth2/OIDC integration."""

from fastapi import HTTPException, Request
from usso import UserData, USSOException

from apps.identity.user.models import User
from apps.tenant.services import get_tenant
from server.exceptions import UnauthorizedError


async def get_current_user(request: Request) -> User:
    """Get current authenticated user from request."""
    tenant = await get_tenant(request)

    # Get user data from JWT token
    usso_auth = tenant.get_auth("access")
    payload: UserData = usso_auth(request)

    # Get user from database
    user = await User.get_item(uid=payload.sub, tenant_id=tenant.uid)
    if not user:
        raise UnauthorizedError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )

    return user


async def get_current_user_optional(request: Request) -> User | None:
    """Get current authenticated user from request, return None if not authenticated."""
    try:
        return await get_current_user(request)
    except (HTTPException, USSOException):
        return None
