"""Secure session token helpers for sensitive actions."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import Request
from fastapi_mongo_base.utils import timezone
from usso.user import TokenType

from apps.identity.user.models import User
from apps.tenant.models import Tenant
from server.exceptions import ForbiddenError, UnauthorizedError

from ..enums import AuthSecret, LoginStatus
from ..schemas import PayloadData

# Methods that prove possession beyond a shared password (tenant MFA / OTP paths).
SECURE_AUTH_METHODS: frozenset[str] = frozenset({
    AuthSecret.TOTP.value,
    AuthSecret.EMAIL_OTP.value,
    AuthSecret.PHONE_OTP.value,
    AuthSecret.MAGIC_LINK.value,
    AuthSecret.WEBAUTHN.value,
    AuthSecret.BACKUP_CODES.value,
})


def is_secure_amr(amr: list[str] | None) -> bool:
    """Return True when AMR includes at least one secure authentication method."""
    if not amr:
        return False
    return any(method in SECURE_AUTH_METHODS for method in amr)


def is_secure_method(method: AuthSecret | str | None) -> bool:
    """Return True when the login method qualifies for issuing a secure token."""
    if method is None:
        return False
    value = method.value if isinstance(method, AuthSecret) else str(method)
    return value in SECURE_AUTH_METHODS


def create_secure_token_payload(
    *,
    user: User,
    tenant: Tenant,
    amr: list[str] | None = None,
    iss: str | None = None,
) -> PayloadData:
    """
    Issue a short-lived secure session JWT.

    TTL comes from ``tenant.config.token.secure_session_timeout``.
    """
    now = int(datetime.now(timezone.tz).timestamp())
    expires_in = tenant.config.token.get_timeout("secure")
    payload = PayloadData(
        jti=str(uuid.uuid4()),
        token_type=TokenType.SECURE_TOKEN,
        iss=iss or tenant.primary_url,
        aud=iss or tenant.primary_url,
        iat=now,
        exp=now + expires_in,
        sub=user.uid,
        tenant_id=user.tenant_id,
        amr=list(amr or []),
    )
    payload.token = tenant.sign_jwt(
        payload.model_dump(exclude_none=True),
        hmac=True,
    )
    return payload


def extract_secure_token(request: Request) -> str | None:
    """Read secure token from cookie, Authorization bearer, or x-usso-secure-token."""
    cookie = request.cookies.get(f"usso-{TokenType.SECURE_TOKEN.value}-token")
    if cookie:
        return cookie
    header = request.headers.get("x-usso-secure-token")
    if header:
        return header
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("secure "):
        return auth[7:].strip()
    return None


def require_secure_token(
    *,
    request: Request,
    tenant: Tenant,
    user_id: str | None = None,
) -> PayloadData:
    """
    Validate the secure session token for a sensitive action.

    Raises UnauthorizedError when missing/invalid/expired, ForbiddenError when
    the token subject does not match ``user_id``.
    """
    raw = extract_secure_token(request)
    if not raw:
        raise UnauthorizedError(
            error_code="secure_token_required",
            detail="Secure token required",
            message={
                "en": "A secure token is required for this action.",
                "fa": "برای این کار به تأیید امن نیاز دارید.",
            },
        )

    try:
        payload = tenant.secure_auth.user_data_from_token(
            raw,
            raise_exception=True,
            expected_token_type=TokenType.SECURE_TOKEN.value,
        )
    except Exception as exc:
        raise UnauthorizedError(
            error_code="secure_token_invalid",
            detail="Invalid or expired secure token",
            message={
                "en": "Secure token is invalid or expired. Please verify again.",
                "fa": "تأیید امن نامعتبر یا منقضی است. لطفاً دوباره تأیید کنید.",
            },
        ) from exc

    if payload is None:
        raise UnauthorizedError(
            error_code="secure_token_invalid",
            detail="Invalid or expired secure token",
            message={
                "en": "Secure token is invalid or expired. Please verify again.",
                "fa": "تأیید امن نامعتبر یا منقضی است. لطفاً دوباره تأیید کنید.",
            },
        )

    # user_data_from_token may return UserData; normalize to PayloadData fields
    sub = getattr(payload, "sub", None) or getattr(payload, "user_id", None)
    if user_id is not None and sub != user_id:
        raise ForbiddenError(
            error_code="secure_token_user_mismatch",
            detail="Secure token does not match user",
            message={
                "en": "Secure token does not match this user.",
                "fa": "تأیید امن با این کاربر هم‌خوانی ندارد.",
            },
        )

    if isinstance(payload, PayloadData):
        return payload
    return PayloadData(
        jti=getattr(payload, "jti", None),
        token_type=TokenType.SECURE_TOKEN,
        iss=getattr(payload, "iss", None),
        aud=getattr(payload, "aud", None),
        iat=getattr(payload, "iat", None),
        exp=getattr(payload, "exp", None),
        sub=sub,
        tenant_id=getattr(payload, "tenant_id", None),
        amr=getattr(payload, "amr", None),
        claims=getattr(payload, "claims", None),
    )


def maybe_attach_secure_token(
    *,
    payloads: dict,
    user: User,
    tenant: Tenant,
    status: LoginStatus,
    amr: list[str] | None,
    iss: str | None = None,
) -> dict:
    """Attach a secure session token when login completed via a secure AMR."""
    if status != LoginStatus.COMPLETED or not is_secure_amr(amr):
        return payloads
    payloads[TokenType.SECURE_TOKEN] = create_secure_token_payload(
        user=user,
        tenant=tenant,
        amr=amr,
        iss=iss,
    )
    return payloads
