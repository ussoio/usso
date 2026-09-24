"""OAuth 2.0 Device Authorization Grant (RFC 8628) helpers and services."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi_mongo_base.utils import timezone

from apps.identity.user.models import User
from apps.tenant.models import Tenant
from server.exceptions import BadRequestError, NotFoundError

from . import models
from .schemas import (
    GrantType,
    OuathDeviceAuthorizationResponseSchema,
    OuathDeviceAuthorizationStatus,
    Scope,
    TokenResponseSchema,
)
from .services import create_tokens, validate_client

USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DEFAULT_EXPIRES_IN = 600
DEFAULT_INTERVAL = 5
SLOW_DOWN_INCREMENT = 5


def generate_user_code() -> str:
    """Generate a human-typable user_code (XXXX-XXXX)."""
    raw = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def generate_device_code() -> str:
    """Generate a high-entropy device_code."""
    return secrets.token_urlsafe(48)


def normalize_user_code(user_code: str) -> str:
    """Normalize user_code for case/separator-insensitive lookup."""
    return "".join(ch for ch in user_code.upper() if ch.isalnum())


def build_verification_uri_complete(verification_uri: str, user_code: str) -> str:
    """Append user_code to the verification URI."""
    sep = "&" if "?" in verification_uri else "?"
    return f"{verification_uri}{sep}{urlencode({'user_code': user_code})}"


def client_allows_device_code(client: models.OAuthClient) -> bool:
    """Return True when the client is allowed to use the device grant."""
    grants = [
        g.value if isinstance(g, GrantType) else str(g)
        for g in (client.grant_types or [])
    ]
    return GrantType.DEVICE_CODE.value in grants


def resolve_device_scopes(client: models.OAuthClient, scope: str | None) -> list[str]:
    """Intersect requested scopes with the client's allowed scopes."""

    def _scope_value(item: object) -> str:
        if isinstance(item, Scope):
            return item.value
        value = getattr(item, "value", None)
        if isinstance(value, str):
            return value
        return str(item)

    allowed = [_scope_value(s) for s in (client.allowed_scopes or [])]
    requested = [s.strip() for s in (scope or "").split() if s.strip()]
    if not requested:
        return [Scope.OPENID.value] if Scope.OPENID.value in allowed else allowed[:1]
    return [s for s in requested if s in allowed]


def assert_poll_interval(
    auth: models.OuathDeviceAuthorization,
    *,
    now: datetime | None = None,
) -> None:
    """Raise slow_down when the client polls faster than ``interval``."""
    now = now or datetime.now(timezone.tz)
    if auth.last_polled_at is None:
        return
    last = auth.last_polled_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.tz)
    elapsed = (now - last).total_seconds()
    if elapsed < auth.interval:
        auth.interval = auth.interval + SLOW_DOWN_INCREMENT
        raise BadRequestError(
            error_code="slow_down",
            detail="Polling too frequently",
            message={
                "en": "Slow down.",
                "fa": "لطفاً با فاصله بیشتری دوباره تلاش کنید.",
            },
        )


def raise_if_not_ready(auth: models.OuathDeviceAuthorization) -> None:
    """Raise the RFC 8628 token-endpoint error for non-ready states."""
    now = datetime.now(timezone.tz)
    expires_at = auth.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.tz)
    if auth.is_consumed or now > expires_at:
        raise BadRequestError(
            error_code="expired_token",
            detail="Device code expired",
            message={
                "en": "Device code expired.",
                "fa": "کد دستگاه منقضی شده است.",
            },
        )
    if auth.status == OuathDeviceAuthorizationStatus.DENIED:
        raise BadRequestError(
            error_code="access_denied",
            detail="User denied the request",
            message={
                "en": "Access denied.",
                "fa": "دسترسی رد شد.",
            },
        )
    if auth.status == OuathDeviceAuthorizationStatus.PENDING:
        raise BadRequestError(
            error_code="authorization_pending",
            detail="Authorization pending",
            message={
                "en": "Authorization pending.",
                "fa": "در انتظار تأیید کاربر.",
            },
        )


async def create_device_authorization(
    *,
    tenant: Tenant,
    client: models.OAuthClient,
    scope: str | None = None,
) -> OuathDeviceAuthorizationResponseSchema:
    """Start a device authorization request for an OAuth client."""
    if not client_allows_device_code(client):
        raise BadRequestError(
            error_code="unauthorized_client",
            detail="Client is not allowed to use device_code grant",
            message={
                "en": "Client is not allowed to use device code.",
                "fa": "این ابزار اجازه ورود با کد دستگاه را ندارد.",
            },
        )

    scopes = resolve_device_scopes(client, scope)
    if not scopes:
        raise BadRequestError(
            error_code="invalid_scope",
            detail="No valid scopes requested",
            message={
                "en": "Invalid scope.",
                "fa": "سطح دسترسی درخواستی نامعتبر است.",
            },
        )

    user_code = generate_user_code()
    device_code = generate_device_code()
    verification_uri = tenant.get_frontend_url("oauth_device")
    expires_in = DEFAULT_EXPIRES_IN

    auth = models.OuathDeviceAuthorization(
        tenant_id=tenant.uid,
        user_id=client.user_id,
        client_id=client.client_id,
        device_code=device_code,
        user_code=user_code,
        user_code_normalized=normalize_user_code(user_code),
        scope=scopes,
        status=OuathDeviceAuthorizationStatus.PENDING,
        interval=DEFAULT_INTERVAL,
        expires_at=datetime.now(timezone.tz) + timedelta(seconds=expires_in),
    )
    await auth.save()

    return OuathDeviceAuthorizationResponseSchema(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=build_verification_uri_complete(
            verification_uri, user_code
        ),
        expires_in=expires_in,
        interval=DEFAULT_INTERVAL,
    )


async def get_pending_by_user_code(
    *, tenant_id: str, user_code: str
) -> models.OuathDeviceAuthorization:
    """Load a still-pending device authorization by user_code."""
    normalized = normalize_user_code(user_code)
    auth = await models.OuathDeviceAuthorization.find_one({
        "tenant_id": tenant_id,
        "user_code_normalized": normalized,
        "status": OuathDeviceAuthorizationStatus.PENDING,
        "is_deleted": False,
        "expires_at": {"$gt": datetime.now(timezone.tz)},
    })
    if auth is None:
        raise NotFoundError(
            error_code="invalid_user_code",
            detail="Invalid or expired user_code",
            message={
                "en": "Invalid or expired code.",
                "fa": "کد نامعتبر یا منقضی است.",
            },
        )
    return auth


async def approve_device_authorization(
    *,
    tenant: Tenant,
    user: User,
    user_code: str,
    approve: bool,
    granted_scope: list[str] | None = None,
) -> models.OuathDeviceAuthorization:
    """Approve or deny a pending device authorization as the logged-in user."""
    auth = await get_pending_by_user_code(tenant_id=tenant.uid, user_code=user_code)
    if not approve:
        auth.status = OuathDeviceAuthorizationStatus.DENIED
        auth.authorized_user_id = user.uid
        await auth.save()
        return auth

    client = await validate_client(auth.client_id, tenant)
    allowed = resolve_device_scopes(client, " ".join(auth.scope))
    scopes = [s for s in (granted_scope or auth.scope) if s in allowed] or allowed
    auth.status = OuathDeviceAuthorizationStatus.AUTHORIZED
    auth.authorized_user_id = user.uid
    auth.granted_scope = scopes
    await auth.save()
    return auth


async def exchange_device_code(
    *,
    tenant: Tenant,
    client_id: str,
    device_code: str,
) -> TokenResponseSchema:
    """Poll/exchange a device_code for tokens after user approval."""
    client = await validate_client(client_id, tenant)
    if not client_allows_device_code(client):
        raise BadRequestError(
            error_code="unauthorized_client",
            detail="Client is not allowed to use device_code grant",
            message={
                "en": "Client is not allowed to use device code.",
                "fa": "این ابزار اجازه ورود با کد دستگاه را ندارد.",
            },
        )

    auth = await models.OuathDeviceAuthorization.find_one({
        "tenant_id": tenant.uid,
        "client_id": client.client_id,
        "device_code": device_code,
        "is_deleted": False,
    })
    if auth is None:
        raise BadRequestError(
            error_code="invalid_grant",
            detail="Invalid device_code",
            message={
                "en": "Invalid device code.",
                "fa": "کد دستگاه نامعتبر است.",
            },
        )

    try:
        assert_poll_interval(auth)
    except BadRequestError:
        await auth.save()
        raise

    auth.last_polled_at = datetime.now(timezone.tz)
    await auth.save()

    raise_if_not_ready(auth)

    if auth.status != OuathDeviceAuthorizationStatus.AUTHORIZED:
        raise BadRequestError(
            error_code="invalid_grant",
            detail="Device authorization is not approved",
            message={
                "en": "Device authorization is not approved.",
                "fa": "ورود با کد دستگاه تأیید نشده است.",
            },
        )

    consume_result = (
        await models.OuathDeviceAuthorization.get_pymongo_collection().update_one(
            {
                "uid": auth.uid,
                "tenant_id": tenant.uid,
                "client_id": client.client_id,
                "status": OuathDeviceAuthorizationStatus.AUTHORIZED,
                "is_consumed": False,
                "expires_at": {"$gt": datetime.now(timezone.tz)},
            },
            {"$set": {"is_consumed": True}},
        )
    )
    if consume_result.modified_count != 1:
        raise BadRequestError(
            error_code="expired_token",
            detail="Device code expired or already used",
            message={
                "en": "Device code expired or already used.",
                "fa": "کد دستگاه منقضی شده یا قبلاً استفاده شده است.",
            },
        )
    auth.is_consumed = True

    user = await User.get_item(
        uid=auth.authorized_user_id,
        tenant_id=tenant.uid,
    )
    if user is None:
        raise BadRequestError(
            error_code="invalid_grant",
            detail="Authorized user not found",
            message={
                "en": "Authorized user not found.",
                "fa": "کاربر تأییدکننده پیدا نشد.",
            },
        )

    tokens = await create_tokens(
        client=client,
        user=user,
        tenant=tenant,
        scope=auth.granted_scope or auth.scope,
    )
    return tokens
