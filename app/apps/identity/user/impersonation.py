"""Impersonation modes, scope filtering, OTP consent, and session issuance."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Literal
from urllib.parse import urlencode

from fastapi_mongo_base.utils import timezone
from starlette.datastructures import URL
from usso.authorization import PRIVILEGE_LEVELS, parse_scope
from usso.user import TokenType

from apps.access_control.workspace.models import Workspace
from apps.tenant.models import Tenant
from server.exceptions import (
    BadRequestError,
    TooManyRequestsError,
    UnauthorizedError,
)
from utils.hasher import PasswordHasherService
from utils.net import get_location

from ..auth.enums import AuthIdentifier, AuthSecret, LoginStatus
from ..auth.schemas import LoginFlowResult, PayloadData
from ..auth.services.token import resolve_acr, resolve_signing_level
from ..session.models import AuthSession
from ..session.schemas import SessionType
from .jwt_claims import jwt_claims_for_user
from .models import Credential, User, UserIdentifier
from .schemas import ImpersonationMode

logger = logging.getLogger(__name__)

IMPERSONATION_OTP_PURPOSE = "impersonation"
ConsentKind = Literal["admin", "otp"]

_READ_LEVEL = PRIVILEGE_LEVELS["read"]


def to_readonly_scopes(scopes: list[str] | None) -> list[str]:
    """
    Downgrade JWT scopes so they only authorize read-level actions.

    Wildcard and elevated actions become ``read:...``; scopes that are already
    at or below read level are kept. Deduplicated, order preserved.
    """
    if not scopes:
        return []

    result: list[str] = []
    seen: set[str] = set()
    for scope in scopes:
        action, path_parts, filters = parse_scope(scope)
        level = PRIVILEGE_LEVELS.get(action or "read", _READ_LEVEL)
        if level > _READ_LEVEL or action == "*":
            path = "/".join(path_parts)
            query = f"?{urlencode(filters)}" if filters else ""
            rewritten = f"read:{path}{query}"
        else:
            rewritten = scope
        if rewritten not in seen:
            seen.add(rewritten)
            result.append(rewritten)
    return result


def build_impersonation_amr(
    *, mode: ImpersonationMode, consent: ConsentKind
) -> list[str]:
    """AMR values for an impersonation session."""
    amr = ["impersonation"]
    if mode == ImpersonationMode.READONLY:
        amr.append("impersonation_readonly")
    if consent == "otp":
        amr.append("impersonation_otp")
    return amr


def build_impersonation_claims(
    *,
    user: User,
    impersonated_by: str,
    mode: ImpersonationMode,
    consent: ConsentKind,
) -> dict:
    """JWT/session claims that identify the acting admin and mode."""
    return jwt_claims_for_user(
        user,
        extra={
            "impersonated_by": impersonated_by,
            "impersonation_mode": mode.value,
            "impersonation_consent": consent,
        },
    )


def apply_impersonation_mode_to_scopes(
    scopes: list[str] | None, *, mode: ImpersonationMode
) -> list[str]:
    """Apply mode-specific scope filtering for issuance."""
    if mode == ImpersonationMode.READONLY:
        return to_readonly_scopes(scopes)
    return list(scopes or [])


def merge_impersonation_claims_for_workspace(
    *,
    user: User,
    previous_session: AuthSession,
) -> tuple[dict | None, SessionType, list[str] | None]:
    """
    Preserve impersonation audit claims when switching workspace mid-session.

    Returns (claims, session_type, mode_for_scope_filter).
    """
    prev = dict(previous_session.claims or {})
    impersonated_by = prev.get("impersonated_by")
    if not impersonated_by:
        return jwt_claims_for_user(user), SessionType.REGULAR_LOGIN, None

    mode_raw = prev.get("impersonation_mode") or ImpersonationMode.FULL.value
    consent = prev.get("impersonation_consent") or "admin"
    return (
        jwt_claims_for_user(
            user,
            extra={
                "impersonated_by": impersonated_by,
                "impersonation_mode": mode_raw,
                "impersonation_consent": consent,
            },
        ),
        SessionType.IMPERSONATION,
        mode_raw,
    )


async def create_impersonation_session(
    *,
    user: User,
    tenant: Tenant,
    impersonated_by: str,
    mode: ImpersonationMode = ImpersonationMode.FULL,
    consent: ConsentKind = "admin",
    user_agent: str | None = None,
    ip: str | None = None,
    aud: str | None = None,
    parent_session_id: str | None = None,
) -> AuthSession:
    """
    Create an impersonation session for a user.

    Same workspace binding as a completed login. Readonly mode strips write
    scopes from the session before tokens are issued.
    """
    from ..auth.services.token import (
        _resolve_login_workspace_id,
        _resolve_token_roles_scopes,
    )

    location = (await get_location(ip) if ip else None) or {}

    login_flow_result = LoginFlowResult(
        status=LoginStatus.COMPLETED,
        user=user,
        amr=build_impersonation_amr(mode=mode, consent=consent),
    )
    workspace_id = await _resolve_login_workspace_id(
        user=user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        workspace_id=None,
    )
    # Personal workspaces may be disabled. In that case impersonation still
    # needs a concrete business workspace so workspace-scoped resources can
    # be opened by the target user.
    if workspace_id is None:
        for candidate_id in user.workspace_ids or []:
            if candidate_id == user.uid:
                continue
            candidate = await Workspace.find_one({
                "uid": candidate_id,
                "tenant_id": user.tenant_id,
                "is_active": True,
                "is_deleted": False,
            })
            if candidate is not None:
                workspace_id = candidate_id
                break
    roles, scopes = await _resolve_token_roles_scopes(
        user=user,
        workspace_id=workspace_id,
        scopes=None,
        roles=None,
    )
    scopes = apply_impersonation_mode_to_scopes(scopes, mode=mode)
    claims = build_impersonation_claims(
        user=user,
        impersonated_by=impersonated_by,
        mode=mode,
        consent=consent,
    )
    amr = build_impersonation_amr(mode=mode, consent=consent)

    session = AuthSession(
        scopes=scopes,
        roles=roles,
        user_id=user.uid,
        tenant_id=user.tenant_id,
        workspace_id=workspace_id,
        aud=aud,
        amr=amr,
        max_age_minutes=max(1, tenant.config.token.refresh_timeout // 60),
        user_agent=user_agent or "unknown",
        ip=ip or "unknown",
        location=location.get("location"),
        session_type=SessionType.IMPERSONATION,
        claims=claims,
        meta_data={
            "impersonated_by": impersonated_by,
            "impersonation_mode": mode.value,
            "impersonation_consent": consent,
            **({"parent_session_id": parent_session_id} if parent_session_id else {}),
        },
    )
    await session.save()
    return session


def create_impersonation_tokens(
    *,
    user: User,
    tenant: Tenant,
    session: AuthSession,
    aud: str | None = None,
    url: URL | str | None = None,
) -> dict[TokenType, PayloadData]:
    """Create access and refresh tokens for an impersonated user."""
    from ..auth.services import get_tenant_url

    now = int(datetime.now(timezone.tz).timestamp())
    iss = get_tenant_url(tenant, url) if url else tenant.primary_url
    results: dict[TokenType, PayloadData] = {}

    for token_type in [TokenType.ACCESS, TokenType.REFRESH]:
        jti = str(uuid.uuid4())
        exp = now + tenant.config.token.get_timeout(token_type.value)

        if token_type == TokenType.REFRESH:
            payload = PayloadData(
                jti=jti,
                token_type=token_type,
                iss=iss,
                aud=iss,
                iat=now,
                exp=exp,
                sub=user.uid,
                tenant_id=user.tenant_id,
                session_id=session.uid,
            )
        else:
            payload = PayloadData(
                jti=jti,
                token_type=token_type,
                iss=iss,
                aud=aud,
                iat=now,
                exp=exp,
                sub=user.uid,
                tenant_id=user.tenant_id,
                session_id=session.uid,
                workspace_id=session.workspace_id,
                roles=session.roles,
                scopes=session.scopes,
                amr=session.amr,
                acr=resolve_acr(session.amr),
                signing_level=resolve_signing_level(session.amr),
                claims=session.claims,
            )

        payload.token = tenant.sign_jwt(
            payload.model_dump(exclude_none=True),
            hmac=(token_type == TokenType.REFRESH),
        )
        results[token_type] = payload

    return results


def _mask_identifier(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{'*' * (len(value) - 4)}{value[-4:]}"


async def _pick_otp_identifier(
    *,
    user: User,
    identifier_type: AuthIdentifier | None,
) -> UserIdentifier:
    identifiers = await user.get_identifiers(not_cached=True)
    active = [i for i in identifiers if i.is_active and not i.is_deleted]
    if identifier_type is not None:
        match = next((i for i in active if i.type == identifier_type), None)
        if match is None:
            raise BadRequestError(
                error_code="identifier_not_found",
                detail=f"User has no {identifier_type} identifier",
                message={
                    "en": f"User has no {identifier_type} for OTP.",
                    "fa": "برای ارسال کد، شناسه مناسب برای این کاربر پیدا نشد.",
                },
            )
        return match

    for preferred in (AuthIdentifier.PHONE, AuthIdentifier.EMAIL):
        match = next((i for i in active if i.type == preferred), None)
        if match is not None:
            return match

    raise BadRequestError(
        error_code="no_otp_destination",
        detail="User has no phone or email for OTP",
        message={
            "en": "User has no phone or email to receive an OTP.",
            "fa": "برای این کاربر شماره یا ایمیلی جهت ارسال کد ثبت نشده.",
        },
    )


async def send_impersonation_otp(
    *,
    user: User,
    tenant: Tenant,
    requested_by: str,
    mode: ImpersonationMode,
    identifier_type: AuthIdentifier | None = None,
    origin: str | None = None,
) -> dict[str, str]:
    """Send OTP to the target user for consented impersonation."""
    from apps.tenant.messaging import services as messaging_services
    from apps.tenant.messaging.channels.base import AbstractChannel

    from ..auth.services.message import _generate_random_otp

    target = await _pick_otp_identifier(user=user, identifier_type=identifier_type)
    channel_type = "sms" if target.type == AuthIdentifier.PHONE else "email"
    resolved_type = AbstractChannel.resolve_channel_type(
        typ=channel_type, tenant=tenant
    )
    channel = AbstractChannel.create_channel(typ=resolved_type, tenant=tenant)

    is_phone = channel.channel_type in AbstractChannel.tenant_phone_channel_types(
        tenant
    )
    method = AuthSecret.PHONE_OTP if is_phone else AuthSecret.EMAIL_OTP

    query = Credential.get_query(
        tenant_id=tenant.uid,
        user_id=user.uid,
        method=method,
        is_active=True,
    )
    pending = [
        c
        for c in await query.to_list()
        if (c.meta_data or {}).get("purpose") == IMPERSONATION_OTP_PURPOSE
    ]
    if len(pending) > 3:
        raise TooManyRequestsError(
            error_code="too_many_requests",
            detail="Too many OTP requests",
            message={
                "en": "Too many OTP requests",
                "fa": "درخواست‌های زیادی ارسال کرده‌اید. لطفاً کمی صبر کنید.",
            },
        )

    for old in pending:
        old.is_active = False
        await old.save()

    otp = _generate_random_otp(tenant.config.auth.otp_length)
    otp_code = f"{otp:0{tenant.config.auth.otp_length}d}"
    credential = Credential(
        tenant_id=tenant.uid,
        user_id=user.uid,
        secret=PasswordHasherService().hash_password(otp_code),
        method=method,
        expires_at=(
            datetime.now(timezone.tz)
            + timedelta(seconds=tenant.config.auth.otp_timeout)
        ),
        meta_data={
            "purpose": IMPERSONATION_OTP_PURPOSE,
            "requested_by": requested_by,
            "impersonation_mode": mode.value,
            "identifier_type": target.type.value,
            "identifier": target.identifier,
        },
    )
    await credential.save()

    template_type = "sms_otp" if is_phone else "email_otp"
    context = {
        "otp_code": otp_code,
        "tenant": tenant,
        "user": user,
        "expiry_minutes": int(tenant.config.auth.otp_timeout / 60),
        "origin": origin or tenant.primary_domain,
    }
    logger.info("Sending impersonation OTP via %s", channel.channel_type)
    await messaging_services.asend(
        tenant=tenant,
        channel=channel.channel_type,
        to=target.identifier,
        template_type=template_type,
        context=context,
    )

    return {
        "status": "otp_sent",
        "channel": str(channel.channel_type),
        "identifier_type": target.type.value,
        "identifier_hint": _mask_identifier(target.identifier),
    }


async def verify_impersonation_otp(
    *,
    user: User,
    tenant: Tenant,
    requested_by: str,
    mode: ImpersonationMode,
    otp: str,
) -> None:
    """Validate and consume an impersonation OTP for the target user."""
    now = datetime.now(timezone.tz)
    candidates = await Credential.get_query(
        tenant_id=tenant.uid,
        user_id=user.uid,
        is_active=True,
        method_in=[AuthSecret.PHONE_OTP, AuthSecret.EMAIL_OTP],
    ).to_list()

    match: Credential | None = None
    for cred in candidates:
        meta = cred.meta_data or {}
        if meta.get("purpose") != IMPERSONATION_OTP_PURPOSE:
            continue
        if meta.get("requested_by") != requested_by:
            continue
        if meta.get("impersonation_mode") != mode.value:
            continue
        if cred.expires_at is not None:
            expires = cred.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.tz)
            if expires < now:
                continue
        verified = cred.secret.startswith(
            "$argon2"
        ) and PasswordHasherService().verify_password(cred.secret, str(otp))
        if verified:
            match = cred
            break

    if match is None:
        raise UnauthorizedError(
            error_code="invalid_otp",
            detail="Invalid or expired OTP",
            message={
                "en": "Invalid or expired OTP.",
                "fa": "کد واردشده نادرست یا منقضی است.",
            },
        )

    await _consume_impersonation_otp(match=match, user=user, tenant=tenant, now=now)


async def _consume_impersonation_otp(
    *, match: Credential, user: User, tenant: Tenant, now: datetime
) -> None:
    """Atomically consume a matched impersonation OTP."""
    consumed = await Credential.get_pymongo_collection().update_one(
        {
            "uid": match.uid,
            "tenant_id": tenant.uid,
            "user_id": user.uid,
            "is_active": True,
            "is_deleted": False,
        },
        {"$set": {"is_active": False, "last_used_at": now}},
    )
    if consumed.modified_count != 1:
        raise UnauthorizedError(
            error_code="invalid_otp",
            detail="Invalid or expired OTP",
            message={
                "en": "Invalid or expired OTP.",
                "fa": "کد واردشده نادرست یا منقضی است.",
            },
        )
    match.is_active = False
    match.last_used_at = now
