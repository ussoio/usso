"""
Token management and authentication response services.

This module provides functions for creating JWT tokens, building login/refresh
responses, managing cookies, and validating sessions.
"""

import re
import uuid
from datetime import datetime

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi_mongo_base.utils import timezone
from jinja2 import StrictUndefined, Template
from starlette.datastructures import URL
from usso import authorization

from server.exceptions import (
    BadRequestError,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from utils.net import get_location

from ....tenant.models import Tenant
from ...session.models import AuthSession
from ...session.schemas import SessionType
from ...user.jwt_claims import jwt_claims_for_user
from ...user.models import User
from ..enums import AuthSecret, AuthStep, LoginStatus
from ..schemas import (
    LoginFlowResult,
    LoginResponse,
    PayloadData,
    RefreshResponse,
    TokenType,
)
from .basics import get_tenant_url

# OIDC-style ACR values derived from AMR strength
ACR_BASIC = "usso:acr:1"
ACR_MFA = "usso:acr:2"
SUPPORTED_ACR_VALUES = [ACR_BASIC, ACR_MFA]

_STRONG_AMR = frozenset({
    AuthSecret.TOTP.value,
    AuthSecret.WEBAUTHN.value,
    AuthSecret.BACKUP_CODES.value,
})
_PASSWORDLESS_AMR = frozenset({
    AuthSecret.WEBAUTHN.value,
    AuthSecret.MAGIC_LINK.value,
})


def resolve_acr(amr: list[str] | None) -> str:
    """Map authentication methods (AMR) to an ACR claim."""
    methods = list(amr or [])
    if len(methods) >= 2 or any(m in _STRONG_AMR for m in methods):
        return ACR_MFA
    return ACR_BASIC


def resolve_signing_level(amr: list[str] | None) -> str | None:
    """
    Derive signing_level from AMR when applicable.

    hardware: WebAuthn/passkey; software: other passwordless; None otherwise.
    """
    methods = list(amr or [])
    if AuthSecret.WEBAUTHN.value in methods:
        return "hardware"
    if any(m in _PASSWORDLESS_AMR for m in methods):
        return "software"
    return None


def collapse_overlapping_scopes(scopes: list[str] | None) -> list[str]:
    """
    Drop scopes that are covered by a broader scope in the same list.

    Keeps JWT/session payloads smaller when user scopes, tenant roles, and
    workspace roles overlap (e.g. read covered by manage, or filtered
    covered by unfiltered).
    """
    if not scopes:
        return []

    unique = list(dict.fromkeys(scopes))
    kept: list[str] = []
    for scope in unique:
        covered = False
        for other in unique:
            if other == scope:
                continue
            if not authorization.is_subset_scope(subset_scope=scope, super_scope=other):
                continue
            # Equivalent scopes: keep the shorter (then lexicographically smaller).
            if authorization.is_subset_scope(subset_scope=other, super_scope=scope):
                if (len(other), other) < (len(scope), scope):
                    covered = True
                    break
                continue
            covered = True
            break
        if not covered:
            kept.append(scope)
    return kept


def _render_scope_template(scope: str, context: dict) -> str:
    """Render a single scope template with the given context."""
    if not scope:
        return scope

    def _repl(m: re.Match[str]) -> str:
        """Replace {var} with {{ var }} if var is in context."""
        key = m.group(1)
        return f"{{{{ {key} }}}}" if key in context else m.group(0)

    rendered = re.sub(r"\{([^{}]+)\}", _repl, scope)
    try:
        return Template(rendered, undefined=StrictUndefined).render(**context)
    except Exception:
        return scope


def expand_scope_templates(
    scopes: list[str],
    user: User,
    workspace_id: str | None = None,
    fanout_workspace_ids: list[str] | None = None,
) -> list[str]:
    """
    Expand scope strings with Jinja2 using user and session context.

    Context is built from user.model_dump(mode="json") plus workspace_id
    and user_id (alias of uid). Use {{ user_id }}, {{ tenant_id }},
    {{ workspace_id }}, or any user field (e.g. {{ uid }}, {{ name }}).
    Supports both Jinja2 {{ var }} and simple {var} placeholders.

    When fanout_workspace_ids is set, each scope is rendered once per id
    (active subtree fan-out). Overlapping scopes are collapsed afterward.
    """
    base_context = user.model_dump(mode="json")
    base_context["user_id"] = user.uid
    targets = fanout_workspace_ids
    if targets is None:
        targets = [workspace_id or user.uid]

    result: list[str] = []
    for s in scopes:
        if not s:
            result.append(s)
            continue
        for target in targets:
            context = {**base_context, "workspace_id": target or user.uid}
            result.append(_render_scope_template(s, context))
    return collapse_overlapping_scopes(result)


async def expand_roles_with_fanout(
    *,
    user: User,
    workspace_id: str | None,
    roles: list | None = None,
    include_user_scopes: bool = True,
) -> list[str]:
    """
    Expand user/role scopes with per-node active-descendant fan-out.

    Tenant-wide roles and direct user.scopes fan out from the login workspace.
    Workspace roles fan out from their own workspace_id node.
    """
    from apps.access_control.role.models import Role
    from apps.access_control.workspace.services import list_active_descendant_ids

    role_models: list[Role] = (
        roles if roles is not None else await user.get_roles(workspace_id)
    )
    expanded: list[str] = []

    login_fanout: list[str] | None = None
    if workspace_id is not None:
        login_fanout = [
            workspace_id,
            *await list_active_descendant_ids(
                tenant_id=user.tenant_id, workspace_id=workspace_id
            ),
        ]

    if include_user_scopes and user.scopes:
        expanded.extend(
            expand_scope_templates(
                list(user.scopes),
                user,
                workspace_id,
                fanout_workspace_ids=login_fanout,
            )
        )

    node_fanout_cache: dict[str, list[str]] = {}
    for role in role_models:
        node_id = role.workspace_id
        if node_id is None:
            fanout = login_fanout
        else:
            if node_id not in node_fanout_cache:
                node_fanout_cache[node_id] = [
                    node_id,
                    *await list_active_descendant_ids(
                        tenant_id=user.tenant_id, workspace_id=node_id
                    ),
                ]
            fanout = node_fanout_cache[node_id]
        expanded.extend(
            expand_scope_templates(
                list(role.scopes or []),
                user,
                node_id or workspace_id,
                fanout_workspace_ids=fanout,
            )
        )

    return collapse_overlapping_scopes(expanded)


def _extract_shared_payload_data(payload: PayloadData, token_type: TokenType) -> dict:
    """
    Extract shared data from the original payload based on token type.

    Args:
        payload: The original payload
        token_type: Type of token being created

    Returns:
        Dictionary containing shared payload data

    """
    if token_type == TokenType.REFRESH:
        # Minimal data for refresh token - only essential fields
        return payload.model_dump(
            include={
                "iss",  # issuer - ضروری برای validation
                "sub",  # subject (user_id) - ضروری برای user identification
                "tenant_id",  # tenant ID - ضروری برای multi-tenant validation
                "session_id",  # session ID - ضروری برای session lookup
                # Note: iat, exp, jti, token_type, aud
                # will be added in _create_token_payload
            }
        )

    # Full data for access token
    return payload.model_dump(
        include={
            "iss",
            "aud",
            "sub",
            "tenant_id",
            "session_id",
            "workspace_id",
            "roles",
            "scopes",
            "amr",
            "acr",
            "signing_level",
            "claims",
        }
    )


def _create_token_payload(
    *,
    shared_data: dict,
    token_type: TokenType,
    now: int,
    session_alive_seconds: int,
    tenant: Tenant,
    session: AuthSession | None = None,
) -> PayloadData:
    """
    Create a new token payload with the specified type.

    Args:
        shared_data: Shared payload data
        token_type: Type of token to create
        now: Current timestamp
        session_alive_seconds: Remaining session time in seconds
        tenant: Tenant context for token signing
        session: AuthSession for enriching access token data

    Returns:
        New PayloadData instance with signed token

    """
    payload_data = {
        **shared_data,
        "jti": str(uuid.uuid4()),
        "token_type": token_type,
        "iat": now,
        "exp": now
        + min(
            tenant.config.token.get_timeout(token_type.value),
            session_alive_seconds,
        ),
    }

    # For refresh tokens, use minimal payload
    if token_type == TokenType.REFRESH:
        # Refresh token audience should be USSO itself
        payload_data["aud"] = payload_data["iss"]

    # For access tokens, enrich with session data
    elif token_type == TokenType.ACCESS and session:
        payload_data.update({
            "workspace_id": session.workspace_id,
            "amr": session.amr,
            "aud": session.aud,
            "scopes": session.scopes,
            "roles": session.roles,
            "claims": session.claims,
        })

    payload = PayloadData(**payload_data)
    payload.token = tenant.sign_jwt(
        payload.model_dump(exclude_none=True),
        hmac=(token_type in [TokenType.REFRESH, TokenType.TEMPORARY_TOKEN]),
    )

    return payload


async def _resolve_login_workspace_id(
    *,
    user: User,
    tenant: Tenant,
    login_flow_result: LoginFlowResult,
    workspace_id: str | None,
) -> str | None:
    """Bind completed login to an active workspace when enabled."""
    from apps.access_control.workspace.models import Workspace
    from apps.access_control.workspace.services import (
        ensure_personal_workspace,
        require_workspace_active,
    )

    if (
        workspace_id is None
        and tenant.config.workspace.enabled
        and login_flow_result.status == LoginStatus.COMPLETED
    ):
        personal = await ensure_personal_workspace(user=user, tenant=tenant)
        if personal.is_active:
            workspace_id = user.uid

        # When personal workspaces are disabled, bind the login to the first
        # active business workspace the account belongs to. Without this
        # fallback the access token has workspace_id=null and every
        # workspace-scoped CDS save fails validation.
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

    if workspace_id is not None:
        await require_workspace_active(
            tenant_id=user.tenant_id, workspace_id=workspace_id
        )
    return workspace_id


async def _resolve_token_roles_scopes(
    *,
    user: User,
    workspace_id: str | None,
    scopes: object,
    roles: object,
) -> tuple[list[str], list[str]]:
    """Resolve roles/scopes for token issuance, with hierarchy fan-out."""
    role_models = None
    if scopes is None or roles is None:
        role_models = await user.get_roles(workspace_id)
    if scopes is None:
        resolved_scopes = await expand_roles_with_fanout(
            user=user,
            workspace_id=workspace_id,
            roles=role_models,
        )
    else:
        resolved_scopes = expand_scope_templates(list(scopes or []), user, workspace_id)
    if roles is None:
        resolved_roles = [role.name for role in role_models or []]
    else:
        resolved_roles = list(roles)  # type: ignore[arg-type]
    return resolved_roles, resolved_scopes


async def create_token_response(
    *,
    user: User,
    tenant: Tenant,
    login_flow_result: LoginFlowResult,
    aud: str | None = None,
    nbf: int | None = None,
    workspace_id: str | None = None,
    user_agent: str | None = None,
    ip: str | None = None,
    temporary_payload: PayloadData | None = None,
    url: URL | str | None = None,
    **kwargs: object,
) -> dict[TokenType, PayloadData]:
    """
    Create token response with access and refresh tokens.

    Args:
        user: User instance to create tokens for.
        tenant: Tenant instance.
        login_flow_result: Result from login flow processing.
        aud: Audience for the token.
        nbf: Not before timestamp.
        workspace_id: Optional workspace ID.
        user_agent: User agent string.
        ip: IP address.
        temporary_payload: Optional temporary token payload.
        url: Optional URL for redirect.
        **kwargs: Additional keyword arguments.

    Returns:
        Dictionary mapping token types to their payloads.

    """
    workspace_id = await _resolve_login_workspace_id(
        user=user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        workspace_id=workspace_id,
    )

    now = int(datetime.now(timezone.tz).timestamp())
    roles, scopes = await _resolve_token_roles_scopes(
        user=user,
        workspace_id=workspace_id,
        scopes=kwargs.get("scopes"),
        roles=kwargs.get("roles"),
    )

    if login_flow_result.status != LoginStatus.COMPLETED:
        token_types = [TokenType.TEMPORARY_TOKEN]
    else:
        token_types = [TokenType.ACCESS, TokenType.REFRESH]

    if not temporary_payload:
        location = (await get_location(ip) if ip else None) or {}
        session = AuthSession(
            scopes=scopes,
            roles=roles,
            user_id=user.uid,
            tenant_id=user.tenant_id,
            workspace_id=workspace_id,
            aud=aud,
            amr=login_flow_result.amr,
            max_age_minutes=max(1, tenant.config.token.refresh_timeout // 60),
            user_agent=user_agent,
            ip=ip,
            location=location.get("location"),
            session_type=SessionType.REGULAR_LOGIN,
            claims=jwt_claims_for_user(user),
        )
        await session.save()
        session_id = session.uid
    else:
        session_id = temporary_payload.session_id

    iss = get_tenant_url(tenant, url) if url else tenant.primary_url

    results: dict[TokenType, PayloadData] = {}

    for token_type in token_types:
        jti = str(uuid.uuid4())
        exp = now + tenant.config.token.get_timeout(token_type.value)

        # Create different payloads based on token type
        if token_type == TokenType.REFRESH:
            # Minimal refresh token payload
            payload = PayloadData(
                jti=jti,
                token_type=token_type,
                iss=iss,
                aud=iss,  # Refresh token aud should be USSO itself
                iat=now,
                exp=exp,
                sub=user.uid,
                tenant_id=user.tenant_id,
                session_id=session_id,
            )
        else:
            # Full payload for access/temporary tokens
            payload = PayloadData(
                jti=jti,
                token_type=token_type,
                iss=iss,
                aud=aud,
                iat=now,
                nbf=nbf,
                exp=exp,
                sub=user.uid,
                tenant_id=user.tenant_id,
                session_id=session_id,
                workspace_id=workspace_id,
                roles=roles,
                scopes=scopes,
                amr=login_flow_result.amr,
                acr=resolve_acr(login_flow_result.amr),
                signing_level=resolve_signing_level(login_flow_result.amr),
                claims=jwt_claims_for_user(user),
            )

        payload.token = tenant.sign_jwt(
            payload.model_dump(exclude_none=True),
            hmac=(token_type in [TokenType.REFRESH, TokenType.TEMPORARY_TOKEN]),
        )
        results[token_type] = payload

    return results


# Cookie and Browser Detection
def is_cookie_auth_preferred(request: Request, tenant_cookie: bool = True) -> bool:
    """
    Determine if the request should use cookie-based authentication.

    Args:
        request: The incoming request.
        tenant_cookie: Whether tenant allows cookie authentication.

    Returns:
        True if cookie auth should be used, False otherwise.

    """
    if not tenant_cookie:
        return False

    if bool(request.cookies):
        return True

    user_agent = request.headers.get("user-agent")
    if user_agent is None:
        return False

    return any(
        browser in user_agent
        for browser in [
            "Mozilla",
            "Chrome",
            "Safari",
        ]
    )


def remove_cookie(
    response: Response,
    token_type: TokenType,
    domain: str,
    *,
    use_parent_domain: bool = True,
    samesite: str = "lax",
    secure: bool = True,
    httponly: bool = True,
) -> None:
    """
    Remove authentication cookies from response.

    Args:
        response: FastAPI response object.
        token_type: Type of token cookie to remove.
        domain: Domain for cookie removal.
        use_parent_domain: Whether to use parent domain.
        samesite: SameSite cookie attribute.
        secure: Whether cookie is secure.
        httponly: Whether cookie is HTTP-only.

    """
    parts = domain.split(".")
    parent_domain = "." + ".".join(parts[-max(len(parts) - 1, 2) :])

    response.delete_cookie(
        f"usso-{token_type.value}-available",
        domain=parent_domain if use_parent_domain else None,
        samesite=samesite,
        secure=secure,
    )
    response.delete_cookie(
        f"usso-{token_type.value}-token",
        httponly=httponly,
        domain=(
            parent_domain
            if token_type == TokenType.ACCESS and use_parent_domain
            else None
        ),
        samesite=samesite,
        secure=secure,
    )


def remove_auth_cookies(response: Response, domain: str, tenant: Tenant) -> Response:
    """
    Remove all authentication cookies from response.

    Args:
        response: FastAPI response object.
        domain: Domain for cookie removal.
        tenant: Tenant instance for configuration.

    Returns:
        Response with cookies removed.

    """
    use_parent_domain = tenant.config.cookie_header_config.cookie_domain == "parent"
    for token_type in TokenType:
        remove_cookie(
            response,
            token_type,
            domain,
            use_parent_domain=use_parent_domain,
            samesite="lax" if use_parent_domain else None,
            secure=tenant.config.cookie_header_config.is_secure,
            httponly=tenant.config.cookie_header_config.is_http_only,
        )
    return response


def attach_auth_cookies_to_response(
    *,
    response: Response,
    tenant: Tenant,
    payloads: dict[TokenType, PayloadData],
    domain: str | None = None,
) -> None:
    """
    Set authentication cookies in the response.

    Args:
        response: The response to set cookies on
        tenant: The tenant
        payloads: The token payloads to set as cookies
        domain: Optional domain for cookies

    """
    use_parent_domain = tenant.config.cookie_header_config.cookie_domain == "parent"
    samesite = "lax"

    domain = domain if domain and domain in tenant.domains else tenant.primary_domain
    parts = domain.split(".")
    parent_domain = "." + ".".join(parts[-max(len(parts) - 1, 2) :])
    now = int(datetime.now(timezone.tz).timestamp())

    if TokenType.TEMPORARY_TOKEN not in payloads:
        remove_cookie(
            response,
            TokenType.TEMPORARY_TOKEN,
            domain,
            use_parent_domain=use_parent_domain,
            samesite=samesite,
            secure=tenant.config.cookie_header_config.is_secure,
            httponly=tenant.config.cookie_header_config.is_http_only,
        )

    for token_type, payload in payloads.items():
        response.set_cookie(
            key=f"usso-{token_type.value}-token",
            value=payload.token,
            httponly=tenant.config.cookie_header_config.is_http_only,
            max_age=payload.exp - now,
            domain=(
                parent_domain
                if token_type == TokenType.ACCESS and use_parent_domain
                else None
            ),
            samesite=samesite,
            secure=tenant.config.cookie_header_config.is_secure,
        )
        response.set_cookie(
            key=f"usso-{token_type.value}-available",
            value="true",
            max_age=payload.exp - now,
            domain=parent_domain if use_parent_domain else None,
            samesite=samesite,
            secure=tenant.config.cookie_header_config.is_secure,
        )

    return response


def build_login_response(
    *,
    request: Request,
    tenant: Tenant,
    payloads: dict[TokenType, PayloadData],
    status: LoginStatus,
    next_step: AuthStep | None = None,
    domain: str | None = None,
) -> Response:
    """
    Generate a login response for the user.

    Args:
        request: The incoming request
        tenant: The tenant
        payloads: The token payloads
        status: The status of the login
        next_step: The next step of the login
        domain: Optional domain for cookies

    Returns:
        A response with LoginResponse body and optional cookies

    """
    # Create LoginResponse body
    tokens = {token_type: payload.token for token_type, payload in payloads.items()}

    # Use the first payload as the base for LoginResponse
    # (they all have the same user data)
    first_payload = next(iter(payloads.values()))
    login_data = LoginResponse(
        **first_payload.model_dump(exclude={"token"}),
        status=status,
        next_step=next_step,
    )

    if not is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        login_data.tokens = tokens

    # Set the response body
    response = JSONResponse(content=login_data.model_dump(exclude_none=True))

    # Attach cookies if cookie auth is preferred
    if is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        attach_auth_cookies_to_response(
            response=response,
            tenant=tenant,
            payloads=payloads,
            domain=domain or request.url.hostname,
        )

    return response


async def check_session_validity(
    *,
    refresh_payload: PayloadData,
    raise_exception: bool = True,
    check_workspace_active: bool = True,
    consume_refresh: bool = True,
) -> AuthSession | None:
    """
    Check if a session is valid based on refresh token payload.

    Args:
        refresh_payload: Payload data from refresh token.
        raise_exception: Whether to raise exception on invalid session.
        check_workspace_active: When True, sessions bound to an inactive
            workspace are rejected.
        consume_refresh: Whether to enforce one-time refresh-token rotation.
            Internal account switching authenticates with a separate opaque
            browser credential and therefore validates, but does not consume,
            a refresh JWT.

    Returns:
        Valid AuthSession instance.

    Raises:
        ResourceError: If session is invalid and raise_exception is True.

    """
    session = await AuthSession.find_one({
        "uid": refresh_payload.session_id,
        "tenant_id": refresh_payload.tenant_id,
        "is_deleted": False,
    })
    if not session or session.is_deleted:
        if not raise_exception:
            return None
        raise UnauthorizedError(
            error_code="session_not_found",
            detail="Session not found",
            message={
                "en": "Session not found",
                "fa": "ورود قبلی پیدا نشد.",
            },
        )
    if raise_exception and (
        session.user_id != refresh_payload.sub
        or session.tenant_id != refresh_payload.tenant_id
    ):
        raise UnauthorizedError(
            error_code="session_mismatch",
            detail="Refresh token does not match its session",
            message={
                "en": "The session is invalid. Please sign in again.",
                "fa": "نشست نامعتبر است. لطفاً دوباره وارد شوید.",
            },
        )
    if raise_exception and session.is_expired:
        raise UnauthorizedError(
            error_code="session_expired",
            detail="Session expired",
            message={
                "en": "Session expired",
                "fa": "ورود قبلی شما منقضی شده. لطفاً دوباره وارد شوید.",
            },
        )
    if raise_exception and check_workspace_active and session.workspace_id:
        from apps.access_control.workspace.services import require_workspace_active

        try:
            await require_workspace_active(
                tenant_id=session.tenant_id,
                workspace_id=session.workspace_id,
            )
        except ForbiddenError:
            raise UnauthorizedError(
                error_code="workspace_not_active",
                detail="Workspace is not active",
                message={
                    "en": "This workspace is not active. Please sign in again.",
                    "fa": "این فضای کاری فعال نیست. لطفاً دوباره وارد شوید.",
                },
            ) from None
    if raise_exception and consume_refresh:
        # Consume only after every session constraint has passed so transient
        # authorization failures do not burn an otherwise valid refresh token.
        await _consume_refresh_token(refresh_payload)
    return session


async def _consume_refresh_token(refresh_payload: PayloadData) -> None:
    """Atomically mark a refresh JWT as used to enforce token rotation."""
    from server import db

    now = int(datetime.now(timezone.tz).timestamp())
    if not refresh_payload.jti or refresh_payload.exp <= now:
        raise UnauthorizedError(
            error_code="invalid_refresh_token",
            detail="Refresh token is invalid or expired",
        )
    if db.redis is None:
        raise ServiceUnavailableError(
            error_code="refresh_rotation_unavailable",
            detail="Refresh-token replay protection is unavailable",
        )
    try:
        acquired = await db.redis.set(
            f"usso:refresh-used:{refresh_payload.tenant_id}:{refresh_payload.jti}",
            "1",
            nx=True,
            ex=max(1, refresh_payload.exp - now),
        )
    except Exception as exc:
        raise ServiceUnavailableError(
            error_code="refresh_rotation_unavailable",
            detail="Refresh-token replay protection is unavailable",
        ) from exc
    if not acquired:
        raise UnauthorizedError(
            error_code="refresh_token_reused",
            detail="Refresh token has already been used",
            message={
                "en": "This refresh token has already been used. Sign in again.",
                "fa": "این توکن نوسازی قبلاً استفاده شده است. دوباره وارد شوید.",
            },
        )


def build_refresh_response(
    *,
    request: Request,
    tenant: Tenant,
    payload: PayloadData,
    session: AuthSession,
) -> Response:
    """
    Generate a refresh response for the user.

    Args:
        request: The incoming request
        tenant: The tenant context
        payload: The original payload containing minimal refresh token data
        session: The authentication session with fresh user data

    Returns:
        A response with RefreshResponse body and optional cookies

    """
    now = int(datetime.now(timezone.tz).timestamp())
    session_alive_seconds = int(session.expire_at.timestamp() - now)

    # Extract minimal data for refresh token (only essential fields)
    refresh_shared_data = _extract_shared_payload_data(payload, TokenType.REFRESH)

    # Extract full data for access token (preserve original aud if present)
    access_shared_data = _extract_shared_payload_data(payload, TokenType.ACCESS)

    # Generate new access token with fresh session data
    access_payload = _create_token_payload(
        shared_data=access_shared_data,
        token_type=TokenType.ACCESS,
        now=now,
        session_alive_seconds=session_alive_seconds,
        tenant=tenant,
        session=session,  # Pass session for fresh data
    )

    # Generate new refresh token with minimal data
    refresh_payload = _create_token_payload(
        shared_data=refresh_shared_data,
        token_type=TokenType.REFRESH,
        now=now,
        session_alive_seconds=session_alive_seconds,
        tenant=tenant,
    )

    payloads = {
        TokenType.ACCESS: access_payload,
        TokenType.REFRESH: refresh_payload,
    }

    tokens = {
        TokenType.ACCESS: access_payload.token,
        TokenType.REFRESH: refresh_payload.token,
    }

    # Create response data
    response_data = RefreshResponse(
        **access_payload.model_dump(exclude={"token"}),
        status=LoginStatus.REFRESHED,
        expires_in=min(
            tenant.config.token.get_timeout(TokenType.ACCESS.value),
            session_alive_seconds,
        ),
    )

    # Add tokens to response if cookie auth is not preferred
    if not is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        response_data.tokens = tokens

    # Create JSON response

    response = JSONResponse(content=response_data.model_dump(exclude_none=True))

    # Attach cookies if cookie auth is preferred
    if is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        attach_auth_cookies_to_response(
            response=response,
            tenant=tenant,
            payloads=payloads,
            domain=request.url.hostname,
        )

    return response


async def get_workspace_roles_scopes(
    *,
    user: User,
    workspace_id: str,
    user_scopes: list[str],
) -> tuple[list[str], list[str]]:
    """Get the roles and scopes for the given workspace."""
    from usso import exceptions as usso_exceptions

    from apps.access_control.workspace.services import has_system_workspace_admin

    user_workspace_ids = list(user.workspace_ids or [])
    is_member = workspace_id in user_workspace_ids
    admin_auth = has_system_workspace_admin(user_scopes=user_scopes)
    if not (is_member or admin_auth):
        raise usso_exceptions.PermissionDenied(
            error_code="workspace_access_denied",
            detail="You do not have access to this workspace",
        )

    if is_member:
        role_models = await user.get_roles(workspace_id)
        scopes = await expand_roles_with_fanout(
            user=user, workspace_id=workspace_id, roles=role_models
        )
        roles = [r.name for r in role_models]
    else:
        role_models = await user.get_roles(None)
        scopes = await expand_roles_with_fanout(
            user=user, workspace_id=workspace_id, roles=role_models
        )
        roles = list(user.roles or [])

    return roles, scopes


async def build_workspace_switch_response(
    *,
    request: Request,
    tenant: Tenant,
    payload: PayloadData,
    session: AuthSession,
    workspace_id: str,
    user_agent: str | None = None,
    ip: str | None = None,
) -> Response:
    """
    Create a new session for the given workspace and return new tokens.

    Membership or system-level workspace admin is required. Returns the same
    shape as refresh (RefreshResponse).
    """
    from apps.access_control.workspace.services import (
        has_system_workspace_admin,
        require_workspace_active,
    )

    if not tenant.config.workspace.enabled:
        raise BadRequestError(
            error_code="workspace_not_enabled",
            detail="Workspace is not enabled for this tenant.",
            message={
                "en": "Workspace is not enabled for this tenant.",
                "fa": "قابلیت فضای کاری در این سامانه فعال نیست.",
            },
        )

    user = await User.get_item(uid=session.user_id, tenant_id=tenant.uid)
    if not user:
        raise NotFoundError(
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )

    await require_workspace_active(tenant_id=user.tenant_id, workspace_id=workspace_id)

    workspace_ids = list(user.workspace_ids or [])
    is_member = workspace_id in workspace_ids
    is_system_admin = has_system_workspace_admin(
        user_scopes=session.scopes or user.scopes or []
    )
    if not (is_member or is_system_admin):
        raise ForbiddenError(
            error_code="workspace_access_denied",
            detail="You do not have access to this workspace",
            message={
                "en": "You do not have access to this workspace",
                "fa": "به این فضای کاری دسترسی ندارید.",
            },
        )

    if is_member:
        role_models = await user.get_roles(workspace_id)
        scopes = await expand_roles_with_fanout(
            user=user, workspace_id=workspace_id, roles=role_models
        )
        roles = [r.name for r in role_models]
        amr = list(session.amr or [])
        assumed_from = None
        meta_data = dict(session.meta_data or {}) or None
    else:
        role_models = await user.get_roles(None)
        scopes = await expand_roles_with_fanout(
            user=user, workspace_id=workspace_id, roles=role_models
        )
        roles = list(user.roles or [])
        amr = [*(session.amr or []), "workspace_admin"]
        assumed_from = session.workspace_id
        meta_data = {**(session.meta_data or {}), "entered_as_admin": True}

    from apps.identity.user.impersonation import (
        apply_impersonation_mode_to_scopes,
        merge_impersonation_claims_for_workspace,
    )
    from apps.identity.user.schemas import ImpersonationMode

    claims, session_type, mode_raw = merge_impersonation_claims_for_workspace(
        user=user, previous_session=session
    )
    if mode_raw == ImpersonationMode.READONLY.value:
        scopes = apply_impersonation_mode_to_scopes(
            scopes, mode=ImpersonationMode.READONLY
        )

    location = (await get_location(ip) if ip else None) or {}

    new_session = AuthSession(
        scopes=scopes,
        roles=roles,
        user_id=user.uid,
        tenant_id=user.tenant_id,
        workspace_id=workspace_id,
        assumed_from_workspace_id=assumed_from,
        aud=session.aud,
        amr=amr,
        max_age_minutes=tenant.config.token.get_timeout(TokenType.REFRESH.value),
        user_agent=user_agent,
        ip=ip,
        location=location.get("location"),
        session_type=session_type,
        claims=claims,
        meta_data=meta_data,
    )
    await new_session.save()

    now = int(datetime.now(timezone.tz).timestamp())
    session_alive_seconds = int(new_session.expire_at.timestamp() - now)

    refresh_shared_data = _extract_shared_payload_data(payload, TokenType.REFRESH)
    refresh_shared_data["session_id"] = new_session.uid
    access_shared_data = _extract_shared_payload_data(payload, TokenType.ACCESS)
    access_shared_data["session_id"] = new_session.uid

    access_payload = _create_token_payload(
        shared_data=access_shared_data,
        token_type=TokenType.ACCESS,
        now=now,
        session_alive_seconds=session_alive_seconds,
        tenant=tenant,
        session=new_session,
    )
    refresh_payload = _create_token_payload(
        shared_data=refresh_shared_data,
        token_type=TokenType.REFRESH,
        now=now,
        session_alive_seconds=session_alive_seconds,
        tenant=tenant,
    )

    payloads = {TokenType.ACCESS: access_payload, TokenType.REFRESH: refresh_payload}
    tokens = {
        TokenType.ACCESS: access_payload.token,
        TokenType.REFRESH: refresh_payload.token,
    }
    response_data = RefreshResponse(
        **access_payload.model_dump(exclude={"token"}),
        status=LoginStatus.REFRESHED,
        expires_in=min(
            tenant.config.token.get_timeout(TokenType.ACCESS.value),
            session_alive_seconds,
        ),
    )
    if not is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        response_data.tokens = tokens

    response = JSONResponse(content=response_data.model_dump(exclude_none=True))
    if is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        attach_auth_cookies_to_response(
            response=response,
            tenant=tenant,
            payloads=payloads,
            domain=request.url.hostname,
        )
    return response
