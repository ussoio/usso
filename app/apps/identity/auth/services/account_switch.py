"""Secure browser-side multi-account and impersonation-return services."""

import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import SplitResult, urlsplit

from fastapi import Request, Response
from fastapi_mongo_base.utils import timezone
from usso import USSOException

from apps.identity.session.models import AuthSession, BrowserAccountSet
from apps.identity.session.schemas import (
    MAX_BROWSER_ACCOUNTS,
    BrowserAccountEntry,
    SessionType,
)
from apps.tenant.models import Tenant
from server.config import Settings
from server.exceptions import ForbiddenError, UnauthorizedError

from ..enums import AuthStep, LoginStatus
from ..schemas import (
    BrowserAccountListResponse,
    BrowserAccountResponse,
    PayloadData,
    TokenType,
)
from .basics import get_tenant_url
from .token import (
    build_login_response,
    build_refresh_response,
    check_session_validity,
    is_cookie_auth_preferred,
)

ACCOUNT_SET_COOKIE = "usso-account-set-token"
_MIN_ACCOUNT_TOKEN_LENGTH = 32
_MAX_ACCOUNT_TOKEN_LENGTH = 256


def _credential_digest(raw_token: str) -> str:
    """Hash the opaque browser credential before database lookup/storage."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _expires_at(tenant: Tenant) -> datetime:
    lifetime = max(1, tenant.config.token.refresh_timeout)
    return datetime.now(timezone.tz) + timedelta(seconds=lifetime)


def _aware_datetime(value: datetime) -> datetime:
    """Normalize MongoDB's timezone-naive UTC datetimes for safe comparison."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.tz)
    return value.astimezone(timezone.tz)


def _normalized_origin(parts: SplitResult) -> tuple[str, str, int] | None:
    """Return a strict origin tuple, rejecting credentials and non-origins."""
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        return None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return parts.scheme, parts.hostname.lower().rstrip("."), port


def is_same_origin_request(request: Request) -> bool:
    """Check the browser Origin header against the exact request origin."""
    origin = request.headers.get("origin")
    if not origin or origin == "null":
        return False
    supplied = _normalized_origin(urlsplit(origin))
    expected = _normalized_origin(urlsplit(str(request.base_url)))
    return supplied is not None and supplied == expected


def require_same_origin_request(request: Request) -> None:
    """Protect account-set mutations from cookie-based CSRF."""
    if not is_same_origin_request(request):
        raise ForbiddenError(
            error_code="account_switch_origin_mismatch",
            detail="Account switching requires an exact same-origin request",
            message={
                "en": "Account switching is allowed only from this sign-in site.",
                "fa": "تغییر حساب فقط از همین صفحهٔ ورود مجاز است.",
            },
        )


def attach_account_set_cookie(
    *, response: Response, tenant: Tenant, raw_token: str
) -> None:
    """Attach the host-only opaque account-set credential."""
    response.set_cookie(
        key=ACCOUNT_SET_COOKIE,
        value=raw_token,
        max_age=max(1, tenant.config.token.refresh_timeout),
        path=Settings.base_path,
        secure=tenant.config.cookie_header_config.is_secure,
        httponly=True,
        samesite="lax",
    )


async def _load_account_set(
    *, tenant: Tenant, raw_token: str | None
) -> BrowserAccountSet | None:
    if not raw_token or not (
        _MIN_ACCOUNT_TOKEN_LENGTH <= len(raw_token) <= _MAX_ACCOUNT_TOKEN_LENGTH
    ):
        return None
    account_set = await BrowserAccountSet.find_one({
        "tenant_id": tenant.uid,
        "credential_digest": _credential_digest(raw_token),
        "is_deleted": False,
    })
    if not account_set or _aware_datetime(account_set.expires_at) <= datetime.now(
        timezone.tz
    ):
        return None
    return account_set


async def _require_account_set(
    *, request: Request, tenant: Tenant
) -> tuple[BrowserAccountSet, str]:
    raw_token = request.cookies.get(ACCOUNT_SET_COOKIE)
    account_set = await _load_account_set(tenant=tenant, raw_token=raw_token)
    if not account_set or raw_token is None:
        raise UnauthorizedError(
            error_code="account_set_required",
            detail="Browser account set not found or expired",
            message={
                "en": "No saved sign-in is available in this browser.",
                "fa": "ورود ذخیره‌شده‌ای در این مرورگر وجود ندارد.",
            },
        )
    return account_set, raw_token


async def _prune_account_set(
    account_set: BrowserAccountSet,
) -> dict[str, AuthSession]:
    """Drop entries whose tenant-bound sessions are gone or expired."""
    session_ids = [entry.session_id for entry in account_set.entries]
    sessions = (
        await AuthSession.find({
            "tenant_id": account_set.tenant_id,
            "uid": {"$in": session_ids},
            "is_deleted": False,
        }).to_list()
        if session_ids
        else []
    )
    by_id = {session.uid: session for session in sessions if not session.is_expired}
    entries = [
        entry
        for entry in account_set.entries
        if (
            (session := by_id.get(entry.session_id)) is not None
            and session.user_id == entry.user_id
        )
    ]
    if len(entries) != len(account_set.entries):
        account_set.entries = entries
        if account_set.active_session_id not in by_id:
            account_set.active_session_id = None
        await account_set.save()
    return {
        entry.session_id: by_id[entry.session_id]
        for entry in account_set.entries
        if entry.session_id in by_id
    }


def _upsert_entry(
    account_set: BrowserAccountSet,
    session: AuthSession,
    *,
    now: datetime,
) -> None:
    """Keep only the most recent session for each linked user."""
    previous = next(
        (entry for entry in account_set.entries if entry.user_id == session.user_id),
        None,
    )
    entries = [
        entry for entry in account_set.entries if entry.user_id != session.user_id
    ]
    if len(entries) >= MAX_BROWSER_ACCOUNTS:
        entries = sorted(
            entries,
            key=lambda entry: _aware_datetime(entry.last_used_at),
            reverse=True,
        )[: MAX_BROWSER_ACCOUNTS - 1]
    entries.append(
        BrowserAccountEntry(
            user_id=session.user_id,
            session_id=session.uid,
            session_type=session.session_type,
            added_at=previous.added_at if previous else now,
            last_used_at=now,
        )
    )
    account_set.entries = entries


async def _previous_refresh_session(
    *, request: Request, tenant: Tenant
) -> AuthSession | None:
    """Resolve the pre-login refresh session without consuming its JWT."""
    refresh_token = request.cookies.get("usso-refresh-token")
    if not refresh_token:
        return None
    try:
        payload = tenant.refresh_auth.user_data_from_token(
            refresh_token,
            raise_exception=True,
            expected_token_type="refresh",  # ruff:ignore[hardcoded-password-func-arg]
        )
        return await check_session_validity(
            refresh_payload=payload,
            consume_refresh=False,
        )
    except (USSOException, TypeError, ValueError):
        return None


async def remember_browser_login(
    *,
    request: Request,
    response: Response,
    tenant: Tenant,
    payloads: dict[TokenType, PayloadData],
) -> None:
    """Add a completed cookie login and its prior account to the browser set."""
    new_payload = payloads.get(TokenType.REFRESH)
    if not new_payload or not new_payload.session_id or not new_payload.sub:
        return

    # POST requests may reuse an existing account set only when the browser
    # proves exact same-origin context. OAuth/magic-link callback GETs already
    # carry their own one-time state/token binding.
    may_reuse = request.method in {"GET", "HEAD"} or is_same_origin_request(request)
    raw_token = request.cookies.get(ACCOUNT_SET_COOKIE) if may_reuse else None
    account_set = await _load_account_set(tenant=tenant, raw_token=raw_token)
    if account_set is None:
        raw_token = secrets.token_urlsafe(32)
        account_set = BrowserAccountSet(
            tenant_id=tenant.uid,
            credential_digest=_credential_digest(raw_token),
            expires_at=_expires_at(tenant),
        )

    await _prune_account_set(account_set)
    now = datetime.now(timezone.tz)
    if may_reuse:
        previous_session = await _previous_refresh_session(
            request=request,
            tenant=tenant,
        )
        if previous_session is not None:
            _upsert_entry(account_set, previous_session, now=now)

    new_session = await AuthSession.find_one({
        "uid": new_payload.session_id,
        "user_id": new_payload.sub,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if new_session is None or new_session.is_expired:
        raise UnauthorizedError(
            error_code="new_session_not_found",
            detail="The newly issued session could not be linked",
        )

    _upsert_entry(account_set, new_session, now=now)
    account_set.active_session_id = new_session.uid
    account_set.expires_at = _expires_at(tenant)
    await account_set.save()
    attach_account_set_cookie(
        response=response,
        tenant=tenant,
        raw_token=raw_token,
    )


async def build_browser_login_response(
    *,
    request: Request,
    tenant: Tenant,
    payloads: dict[TokenType, PayloadData],
    status: LoginStatus,
    next_step: AuthStep | None = None,
    domain: str | None = None,
) -> Response:
    """Build a login response and remember completed browser-cookie sessions."""
    response = build_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=status,
        next_step=next_step,
        domain=domain,
    )
    if (
        TokenType.ACCESS in payloads
        and TokenType.REFRESH in payloads
        and is_cookie_auth_preferred(
            request=request,
            tenant_cookie=(
                tenant.config.cookie_header_config.header_or_cookie == "cookie"
            ),
        )
    ):
        await remember_browser_login(
            request=request,
            response=response,
            tenant=tenant,
            payloads=payloads,
        )
    return response


async def list_browser_accounts(
    *, request: Request, tenant: Tenant
) -> BrowserAccountListResponse:
    """List only live, tenant-local accounts linked to this browser."""
    account_set, _ = await _require_account_set(request=request, tenant=tenant)
    sessions = await _prune_account_set(account_set)

    from apps.identity.user.models import User
    from apps.identity.user.schemas import ActivationStatus

    user_ids = [entry.user_id for entry in account_set.entries]
    users = (
        await User.find({
            "tenant_id": tenant.uid,
            "uid": {"$in": user_ids},
            "is_deleted": False,
        }).to_list()
        if user_ids
        else []
    )
    users_by_id = {
        user.uid: user
        for user in users
        if (
            user.is_active
            and not user.is_limited
            and user.activation_status == ActivationStatus.ACTIVE
        )
    }
    visible_entries = [
        entry
        for entry in account_set.entries
        if entry.session_id in sessions and entry.user_id in users_by_id
    ]
    if len(visible_entries) != len(account_set.entries):
        account_set.entries = visible_entries
        if account_set.active_session_id not in {
            entry.session_id for entry in visible_entries
        }:
            account_set.active_session_id = None
        await account_set.save()

    visible_entries.sort(
        key=lambda entry: (
            entry.session_id == account_set.active_session_id,
            _aware_datetime(entry.last_used_at),
        ),
        reverse=True,
    )
    accounts = []
    active_user_id = None
    for entry in visible_entries:
        user = users_by_id[entry.user_id]
        session = sessions[entry.session_id]
        active = entry.session_id == account_set.active_session_id
        if active:
            active_user_id = entry.user_id
        accounts.append(
            BrowserAccountResponse(
                user_id=entry.user_id,
                name=user.name,
                avatar_url=user.avatar_url,
                session_type=session.session_type,
                workspace_id=session.workspace_id,
                active=active,
            )
        )
    return BrowserAccountListResponse(
        accounts=accounts,
        active_user_id=active_user_id,
    )


def _payload_for_session(
    *, request: Request, tenant: Tenant, session: AuthSession
) -> PayloadData:
    """Build the minimal trusted input used to mint tokens for a linked session."""
    return PayloadData(
        iss=get_tenant_url(tenant, request.url),
        aud=session.aud,
        sub=session.user_id,
        tenant_id=session.tenant_id,
        session_id=session.uid,
    )


async def _switch_to_user(
    *,
    request: Request,
    tenant: Tenant,
    user_id: str,
    require_impersonation: bool,
) -> Response:
    require_same_origin_request(request)
    account_set, raw_token = await _require_account_set(
        request=request,
        tenant=tenant,
    )
    sessions = await _prune_account_set(account_set)
    active_session = sessions.get(account_set.active_session_id or "")
    if require_impersonation and (
        active_session is None
        or active_session.session_type != SessionType.IMPERSONATION
    ):
        raise ForbiddenError(
            error_code="impersonation_not_active",
            detail="There is no active impersonation session to return from",
            message={
                "en": "You are not currently impersonating another account.",
                "fa": "در حال حاضر در حالت ورود به‌جای کاربر دیگری نیستید.",
            },
        )

    leaving_impersonation = (
        active_session is not None
        and active_session.session_type == SessionType.IMPERSONATION
        and active_session.user_id != user_id
    )
    if leaving_impersonation:
        original_user_id = (active_session.claims or {}).get("impersonated_by")
        if not isinstance(original_user_id, str) or user_id != original_user_id:
            raise ForbiddenError(
                error_code="impersonation_return_target_mismatch",
                detail="An impersonation session may return only to its initiator",
                message={
                    "en": "Return to the administrator account before switching.",
                    "fa": "پیش از تغییر حساب، به حساب مدیر برگردید.",
                },
            )

    target_entry = next(
        (entry for entry in account_set.entries if entry.user_id == user_id),
        None,
    )
    target_session = sessions.get(target_entry.session_id) if target_entry else None
    if target_session is None:
        raise UnauthorizedError(
            error_code="saved_account_session_expired",
            detail="The selected account session no longer exists",
            message={
                "en": "That saved account has expired. Sign in to it again.",
                "fa": "ورود ذخیره‌شدهٔ این حساب منقضی شده است؛ دوباره وارد شوید.",
            },
        )
    if (
        target_session.session_type == SessionType.IMPERSONATION
        and target_session.uid != account_set.active_session_id
    ):
        raise ForbiddenError(
            error_code="inactive_impersonation_cannot_resume",
            detail="An old impersonation session cannot be resumed",
        )

    from apps.identity.user.models import User
    from apps.identity.user.schemas import ActivationStatus

    target_user = await User.find_one({
        "uid": target_session.user_id,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if (
        target_user is None
        or not target_user.is_active
        or target_user.is_limited
        or target_user.activation_status != ActivationStatus.ACTIVE
    ):
        raise UnauthorizedError(
            error_code="saved_account_unavailable",
            detail="The selected account is not active",
            message={
                "en": (
                    "That account is not available. Sign in again or contact support."
                ),
                "fa": (
                    "این حساب فعال نیست؛ دوباره وارد شوید یا با پشتیبانی تماس بگیرید."
                ),
            },
        )

    payload = _payload_for_session(
        request=request,
        tenant=tenant,
        session=target_session,
    )
    target_session = await check_session_validity(
        refresh_payload=payload,
        consume_refresh=False,
    )
    response = build_refresh_response(
        request=request,
        tenant=tenant,
        payload=payload,
        session=target_session,
    )
    response.headers["Cache-Control"] = "no-store"

    now = datetime.now(timezone.tz)
    target_session.last_used_at = now
    await target_session.save()
    target_entry.last_used_at = now
    account_set.active_session_id = target_session.uid
    account_set.expires_at = _expires_at(tenant)

    if leaving_impersonation and active_session is not None:
        account_set.entries = [
            entry
            for entry in account_set.entries
            if entry.session_id != active_session.uid
        ]
        active_session.is_deleted = True
        await active_session.save()

    await account_set.save()
    attach_account_set_cookie(
        response=response,
        tenant=tenant,
        raw_token=raw_token,
    )
    return response


async def switch_browser_account(
    *, request: Request, tenant: Tenant, user_id: str
) -> Response:
    """Make one saved regular account the active browser account."""
    return await _switch_to_user(
        request=request,
        tenant=tenant,
        user_id=user_id,
        require_impersonation=False,
    )


async def return_from_impersonation(*, request: Request, tenant: Tenant) -> Response:
    """Return to the initiating admin and revoke the impersonation session."""
    require_same_origin_request(request)
    account_set, _ = await _require_account_set(request=request, tenant=tenant)
    sessions = await _prune_account_set(account_set)
    active_session = sessions.get(account_set.active_session_id or "")
    original_user_id = (
        (active_session.claims or {}).get("impersonated_by")
        if active_session is not None
        and active_session.session_type == SessionType.IMPERSONATION
        else None
    )
    if not isinstance(original_user_id, str):
        raise ForbiddenError(
            error_code="impersonation_not_active",
            detail="There is no active impersonation session to return from",
            message={
                "en": "You are not currently impersonating another account.",
                "fa": "در حال حاضر در حالت ورود به‌جای کاربر دیگری نیستید.",
            },
        )
    return await _switch_to_user(
        request=request,
        tenant=tenant,
        user_id=original_user_id,
        require_impersonation=True,
    )
