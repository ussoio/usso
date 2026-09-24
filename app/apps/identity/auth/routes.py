"""
Authentication API routes.

This module provides endpoints for user authentication including login,
logout, password reset, OTP, magic links, passkeys, QR code login, and OAuth.
"""

import logging
from datetime import datetime

from fastapi import (
    APIRouter,
    Depends,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi_mongo_base.utils import timezone
from usso import USSOException
from usso.utils.validators import determine_identifier_type

from apps.captcha.dependencies import check_captcha
from apps.tenant.services import get_request_tenant
from server.exceptions import BadRequestError, UnauthorizedError
from server.rate_limiter import get_rate_limiter
from utils.net import get_client_ip

from ..session.models import AuthSession
from ..session.schemas import SessionType
from ..user.models import User
from .auth_schemas import LoginBody
from .enums import AuthIdentifier, AuthSecret, LoginStatus, OTPDeliveryStatus
from .schemas import (
    AccountSwitchRequest,
    BrowserAccountListResponse,
    Identifier,
    LoginAttemptResponse,
    LoginFlowResult,
    LoginRequest,
    LoginResponse,
    MagicLinkRequest,
    OTPRequest,
    PasskeyAssertion,
    PayloadData,
    QRApproveRequest,
    QRCodeResponse,
    QRStatusResponse,
    RefreshRequest,
    RefreshResponse,
    ResetPasswordRequest,
    SecureTokenRequest,
    VerifyTokenRequest,
    WorkspaceLoginRequest,
)
from .services import (
    TelegramIdTokenSchema,
    approve_qr_session,
    build_browser_login_response,
    build_login_response,
    build_refresh_response,
    build_telegram_login_request,
    build_workspace_switch_response,
    check_otp_needed_and_send,
    check_session_validity,
    claim_approved_qr_user,
    consume_magic_link,
    create_oauth_credential,
    create_oauth_session,
    create_otp,
    create_qr_session,
    create_secure_token_payload,
    create_token_response,
    exchange_oauth_code_for_userinfo,
    extract_secure_token,
    get_qr_session_status,
    is_secure_method,
    list_browser_accounts,
    magic_link_payload,
    maybe_attach_secure_token,
    process_login_flow,
    remove_auth_cookies,
    require_secure_token,
    require_telegram_oauth,
    resolve_login_attempt,
    resolve_oauth_identity,
    return_from_impersonation,
    sanitize_origin,
    sanitize_return_url,
    send_magic_link,
    switch_browser_account,
    telegram_display_name,
    telegram_user_id_from_claims,
    verify_telegram_id_token,
)
from .services.oauth import OAuthIdentity

logger = logging.getLogger(__name__)


def _resolve_oauth_callback_identity(
    *,
    provider: str,
    userinfo: dict,
    secrets_data: object,
) -> OAuthIdentity:
    """Resolve OAuth identity and log UnauthorizedError before re-raising."""
    try:
        return resolve_oauth_identity(
            provider=provider,
            userinfo=userinfo,
            secrets_data=secrets_data,
        )
    except UnauthorizedError as exc:
        logger.warning(
            "oauth_callback identity failed provider=%s error_code=%s detail=%s "
            "claim_keys=%s",
            provider,
            exc.error_code,
            exc.detail,
            sorted(str(key) for key in userinfo),
        )
        raise


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)
router_limited = APIRouter(
    tags=["Authentication"],
    dependencies=[Depends(get_rate_limiter("/auth"))],
)
router_captchaed = APIRouter(
    tags=["Authentication"],
    dependencies=[  #
        Depends(get_rate_limiter("/auth")),
        # Depends(check_captcha),  # ruff:ignore[commented-out-code]
    ],
    # dependencies=[Depends(check_captcha)],  # ruff:ignore[commented-out-code]
)


@router_limited.get("/", response_model=list[str])
async def get_all_route() -> list[str]:
    """
    Get all available authentication routes.

    Returns:
        List of route path strings.

    """
    return [str(route) for route in router_limited.routes]


async def _auto_send_otp(result: object, tenant: object, origin: str | None) -> None:
    """Auto-send OTP for methods marked as SENT."""
    if not result.user or not result.otp_delivery:
        return
    identifiers = await result.user.get_identifiers()
    for method_key, delivery_status in result.otp_delivery.items():
        if delivery_status != OTPDeliveryStatus.SENT:
            continue
        if method_key == AuthSecret.PHONE_OTP:
            phones = [
                i.identifier for i in identifiers if i.type == AuthIdentifier.PHONE
            ]
            for phone in phones:
                await create_otp(
                    otp_request=OTPRequest(
                        type=AuthIdentifier.PHONE,
                        identifier=phone,
                    ),
                    tenant=tenant,
                    origin=origin,
                )
        elif method_key == AuthSecret.EMAIL_OTP:
            emails = [
                i.identifier for i in identifiers if i.type == AuthIdentifier.EMAIL
            ]
            for email in emails:
                await create_otp(
                    otp_request=OTPRequest(
                        type=AuthIdentifier.EMAIL,
                        identifier=email,
                    ),
                    tenant=tenant,
                    origin=origin,
                )


@router_captchaed.post("/login-attempts", response_model=LoginAttemptResponse)
async def login_attempt(
    request: Request,
    data: Identifier,
    _: Response = Depends(check_captcha),
) -> LoginAttemptResponse:
    """
    Start a login attempt: resolve identifier, return available auth methods.

    This endpoint does NOT authenticate. It identifies the user, checks tenant
    config, issues a temporary token, and tells the frontend which auth methods
    are available. If OTP is the only viable method, it auto-sends the OTP.
    """
    from ..user.models import User

    tenant = await get_request_tenant(request)

    result = await resolve_login_attempt(identifier=data, tenant=tenant)

    from .schemas import LoginFlowResult

    payloads = await create_token_response(
        user=result.user or User(tenant_id=tenant.uid),
        tenant=tenant,
        login_flow_result=LoginFlowResult(
            status=result.status,
            user=result.user,
            amr=[],
        ),
        url=request.url,
    )

    origin = request.headers.get("origin")
    origin = sanitize_origin(origin)
    await _auto_send_otp(result, tenant, origin)

    from .services.token import (
        attach_auth_cookies_to_response,
        is_cookie_auth_preferred,
    )

    tokens = {token_type: payload.token for token_type, payload in payloads.items()}
    response_data = LoginAttemptResponse(
        status=result.status,
        next_step=result.next_step,
        otp_delivery=result.otp_delivery,
    )
    if not is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        response_data.tokens = tokens

    from fastapi.responses import JSONResponse

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


@router_captchaed.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    data: LoginRequest | LoginBody,
    _: Response = Depends(check_captcha),
) -> LoginResponse:
    """
    Authenticate user and return login response.

    Args:
        request: The FastAPI request object.
        data: Login request data containing identifier and secret.
        _: Captcha verification dependency.

    Returns:
        LoginResponse with tokens and user information.

    """
    if not isinstance(data, LoginRequest):
        data = data.login_request

    tenant = await get_request_tenant(request)

    temporary_payload = tenant.temporary_auth(request)

    # Process login flow
    login_flow_result = await process_login_flow(
        login_request=data,
        tenant=tenant,
        temporary_payload=temporary_payload,
    )

    client_ip = get_client_ip(request)

    payloads = await create_token_response(
        user=login_flow_result.user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=client_ip,
        url=request.url,
    )
    maybe_attach_secure_token(
        payloads=payloads,
        user=login_flow_result.user,
        tenant=tenant,
        status=login_flow_result.status,
        amr=login_flow_result.amr,
    )

    # check if we should send otp
    if login_flow_result.next_step:
        await check_otp_needed_and_send(
            next_step=login_flow_result.next_step,
            user=login_flow_result.user,
            tenant=tenant,
            origin=request.headers.get("origin"),
            amr=login_flow_result.amr,
        )

    return await build_browser_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        next_step=login_flow_result.next_step,
    )


@router_limited.post("/signin", response_model=LoginResponse)
async def signin(
    request: Request,
    data: LoginBody,
    _: Response = Depends(check_captcha),
) -> LoginResponse:
    """User login."""
    return await login(request=request, data=data.login_request)


@router_limited.get("/refresh", response_model=RefreshResponse)
async def refresh_cookie(request: Request, response: Response) -> RefreshResponse:
    """Refresh access using the HttpOnly refresh cookie (browser clients)."""
    try:
        tenant = await get_request_tenant(request)

        refresh_payload = tenant.refresh_auth(request)

        session = await check_session_validity(refresh_payload=refresh_payload)

        return build_refresh_response(
            request=request,
            tenant=tenant,
            payload=refresh_payload,
            session=session,
        )
    except USSOException:
        response.delete_cookie("usso-refresh-available")
        response.delete_cookie("usso-refresh-token")
        raise


@router_limited.post("/refresh", response_model=RefreshResponse)
async def refresh_body(
    request: Request, response: Response, data: RefreshRequest | None = None
) -> RefreshResponse:
    """Refresh access using a body token or the HttpOnly refresh cookie."""
    try:
        tenant = await get_request_tenant(request)

        if data is not None:
            refresh_payload = tenant.refresh_auth.user_data_from_token(
                data.refresh_token,
                raise_exception=True,
                expected_token_type="refresh",  # ruff:ignore[hardcoded-password-func-arg]
            )
        else:
            refresh_payload = tenant.refresh_auth(request)

        session = await check_session_validity(refresh_payload=refresh_payload)

        return build_refresh_response(
            request=request,
            tenant=tenant,
            payload=refresh_payload,
            session=session,
        )
    except USSOException:
        response.delete_cookie("usso-refresh-available")
        response.delete_cookie("usso-refresh-token")
        raise


@router_limited.post("/workspace-login", response_model=RefreshResponse)
async def workspace_login(
    request: Request, response: Response, data: WorkspaceLoginRequest
) -> RefreshResponse:
    """
    Create a new session for another workspace and return new tokens.

    Requires a valid refresh token (cookie or body). User must have the
    workspace in their workspace_ids.
    """
    try:
        tenant = await get_request_tenant(request)
        if data.refresh_token:
            refresh_payload = tenant.refresh_auth.user_data_from_token(
                data.refresh_token,
                raise_exception=True,
                expected_token_type="refresh",  # ruff:ignore[hardcoded-password-func-arg]
            )
        else:
            refresh_payload = tenant.refresh_auth(request)
        if not refresh_payload:
            raise UnauthorizedError(
                error_code="refresh_token_required",
                detail="Refresh token required (cookie or body)",
                message={
                    "en": "Refresh token required",
                    "fa": "لطفاً دوباره وارد شوید.",
                },
            )
        session = await check_session_validity(refresh_payload=refresh_payload)
        client_ip = get_client_ip(request)
        return await build_workspace_switch_response(
            request=request,
            tenant=tenant,
            payload=refresh_payload,
            session=session,
            workspace_id=data.workspace_id,
            user_agent=request.headers.get("user-agent"),
            ip=client_ip,
        )
    except USSOException:
        logger.exception("Workspace login failed.")
        raise


@router_limited.get("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request) -> Response:
    """End session (GET kept for legacy browser clients)."""
    tenant = await get_request_tenant(request)

    refresh_auth = tenant.refresh_auth
    refresh_auth.raise_exception = False
    refresh_payload = refresh_auth(request)
    if refresh_payload:
        session = await check_session_validity(
            refresh_payload=refresh_payload, raise_exception=False
        )
        if session:
            session.is_deleted = True
            await session.save()

    return remove_auth_cookies(
        response=Response(status_code=status.HTTP_204_NO_CONTENT),
        tenant=tenant,
        domain=(
            request.url.hostname
            if request.url.hostname and request.url.hostname in tenant.domains
            else tenant.primary_domain
        ),
    )


@router_limited.get("/impersonation/exit")
async def exit_impersonation(request: Request) -> Response:
    """Restore the administrator session that started impersonation."""
    tenant = await get_request_tenant(request)
    refresh_payload = tenant.refresh_auth(request)
    if not refresh_payload:
        raise UnauthorizedError(
            error_code="impersonation_session_required",
            detail="An impersonation session is required.",
            message={
                "en": "No impersonation session found.",
                "fa": "نشست impersonation پیدا نشد.",
            },
        )
    session = await check_session_validity(refresh_payload=refresh_payload)
    if session.session_type != SessionType.IMPERSONATION:
        raise BadRequestError(
            error_code="not_impersonating",
            detail="The current session is not an impersonation session.",
            message={
                "en": "You are not impersonating a user.",
                "fa": "در حال حاضر در حالت impersonation نیستید.",
            },
        )
    parent_id = (session.meta_data or {}).get("parent_session_id")
    parent = await AuthSession.get_by_uid(parent_id) if parent_id else None
    if not parent or parent.is_deleted or parent.is_expired:
        raise UnauthorizedError(
            error_code="parent_session_expired",
            detail="The administrator session has expired.",
            message={
                "en": "The administrator session has expired.",
                "fa": "نشست ادمین منقضی شده است.",
            },
        )
    admin = await User.get_by_uid(parent.user_id)
    if not admin or admin.is_deleted:
        raise UnauthorizedError(
            error_code="parent_user_not_found",
            detail="The administrator account no longer exists.",
            message={
                "en": "Administrator account not found.",
                "fa": "حساب ادمین پیدا نشد.",
            },
        )

    from usso.user import TokenType

    from .services.token import _create_token_payload

    now = int(datetime.now(timezone.tz).timestamp())
    alive = int(parent.expire_at.timestamp() - now) if parent.expire_at else 86400
    shared = {
        "iss": tenant.primary_url,
        "aud": parent.aud or tenant.primary_url,
        "sub": parent.user_id,
        "tenant_id": parent.tenant_id,
        "session_id": parent.uid,
    }
    payloads = {
        TokenType.ACCESS: _create_token_payload(
            shared_data=shared,
            token_type=TokenType.ACCESS,
            now=now,
            session_alive_seconds=alive,
            tenant=tenant,
            session=parent,
        ),
        TokenType.REFRESH: _create_token_payload(
            shared_data=shared,
            token_type=TokenType.REFRESH,
            now=now,
            session_alive_seconds=alive,
            tenant=tenant,
        ),
    }
    session.is_deleted = True
    await session.save()
    return build_login_response(
        request=request, tenant=tenant, payloads=payloads, status=LoginStatus.COMPLETED
    )


@router_limited.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_post(request: Request) -> Response:
    """End session."""
    return await logout(request)


@router_limited.get("/accounts", response_model=BrowserAccountListResponse)
async def get_browser_accounts(
    request: Request,
    response: Response,
) -> BrowserAccountListResponse:
    """List live accounts saved in this browser for the current tenant."""
    tenant = await get_request_tenant(request)
    result = await list_browser_accounts(request=request, tenant=tenant)
    response.headers["Cache-Control"] = "no-store"
    return result


@router_limited.post("/accounts/switch", response_model=RefreshResponse)
async def switch_account(request: Request, data: AccountSwitchRequest) -> Response:
    """Make a saved account active and rotate the browser auth cookies."""
    tenant = await get_request_tenant(request)
    return await switch_browser_account(
        request=request,
        tenant=tenant,
        user_id=data.user_id,
    )


@router_limited.post("/impersonation/return", response_model=RefreshResponse)
async def impersonation_return(request: Request) -> Response:
    """Return to the initiating admin and revoke the impersonation session."""
    tenant = await get_request_tenant(request)
    return await return_from_impersonation(request=request, tenant=tenant)


@router_captchaed.post("/request-magic-link")
async def magic_link_request(
    request: Request,
    response: Response,
    data: MagicLinkRequest,
    _: None = Depends(get_rate_limiter("/auth/request-magic-link")),
    __: Response = Depends(check_captcha),
) -> None:
    """Request magic link."""
    tenant = await get_request_tenant(request)
    try:
        await send_magic_link(
            tenant=tenant, origin=request.headers.get("origin"), data=data
        )
    except UnauthorizedError as exc:
        # Do not disclose whether an account exists when registration is closed.
        if exc.error_code != "registration_closed":
            raise
    return {"status": "success"}


@router_limited.get("/magic-link")
async def login_by_magic_link(
    request: Request, response: Response, token: str
) -> Response:
    """Login using magic link."""
    tenant = await get_request_tenant(request)

    payload, pem, jwks_url, maximum_age = magic_link_payload(token, tenant, request.url)
    await consume_magic_link(payload, tenant)
    # check if the payload has something else (phone, email, username, national_id, id)
    identifier_type, identifier = determine_identifier_type(payload)
    if not identifier or not identifier_type:
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Invalid token",
            message={
                "en": "Invalid token",
                "fa": "لینک ورود نامعتبر است.",
            },
        )

    login_request = LoginRequest(
        type=identifier_type,
        identifier=identifier,
        method=AuthSecret.MAGIC_LINK,
        secret=token,
    )

    # Process login flow
    login_flow_result = await process_login_flow(
        login_request=login_request,
        tenant=tenant,
        temporary_payload=None,
        pem=pem,
        jwks_url=jwks_url,
        maximum_age=maximum_age,
        magic_link_verified=True,
    )

    client_ip = get_client_ip(request)

    payloads = await create_token_response(
        user=login_flow_result.user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=client_ip,
        url=request.url,
    )
    maybe_attach_secure_token(
        payloads=payloads,
        user=login_flow_result.user,
        tenant=tenant,
        status=login_flow_result.status,
        amr=login_flow_result.amr,
    )
    return await build_browser_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        next_step=login_flow_result.next_step,
    )


@router_limited.get("/passkey")
async def generate_passkey(
    request: Request,
    _: None = Depends(get_rate_limiter("/auth/passkey")),
) -> dict[str, object]:
    """Issue a WebAuthn authentication challenge."""
    from ..user import credential_services

    tenant = await get_request_tenant(request)
    temporary_payload = tenant.temporary_auth(request)
    return await credential_services.generate_authentication_challenge(
        tenant=tenant,
        user_id=temporary_payload.user_id if temporary_payload else None,
        hostname=request.url.hostname,
        origin=request.headers.get("origin"),
    )


@router_limited.post("/passkey", response_model=LoginResponse)
async def passkey(
    request: Request,
    data: PasskeyAssertion,
    _: None = Depends(get_rate_limiter("/auth/passkey")),
) -> Response:
    """Complete login with a WebAuthn assertion."""
    from ..user import credential_services
    from .services.login_flow import activate_user_if_eligible

    tenant = await get_request_tenant(request)
    user = await credential_services.verify_authentication_passkey(
        tenant,
        data.model_dump(),
        request.url.hostname,
        origin=request.headers.get("origin"),
    )
    login_request = LoginRequest(
        type=AuthIdentifier.PASSKEY_ID,
        identifier=user.uid,
        method=AuthSecret.WEBAUTHN,
    )
    is_active = await activate_user_if_eligible(
        user=user, tenant=tenant, login_request=login_request
    )
    login_flow_result = LoginFlowResult(
        status=(
            LoginStatus.COMPLETED if is_active else LoginStatus.VERIFICATION_REQUIRED
        ),
        user=user,
        amr=[AuthSecret.WEBAUTHN.value],
    )
    payloads = await create_token_response(
        user=user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=get_client_ip(request),
        url=request.url,
    )
    maybe_attach_secure_token(
        payloads=payloads,
        user=user,
        tenant=tenant,
        status=login_flow_result.status,
        amr=login_flow_result.amr,
    )
    return await build_browser_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        next_step=login_flow_result.next_step,
    )


@router_limited.get("/qr", response_model=QRCodeResponse)
async def qr_generate(
    request: Request,
    _: None = Depends(get_rate_limiter("/auth/qr")),
    __: Response = Depends(check_captcha),
) -> QRCodeResponse:
    """Create a desktop QR login session (encode ``qr_payload`` as the QR image)."""
    tenant = await get_request_tenant(request)
    return QRCodeResponse(**(await create_qr_session(tenant=tenant)))


@router_limited.get("/qr/status")
async def qr_status(
    request: Request,
    qr_token: str = Query(..., description="QR session token to check status for"),
) -> Response:
    """
    Poll QR session status.

    When the phone has approved, issues login tokens once (WhatsApp-web style).
    """
    from .services import qr_login as qr_services

    tenant = await get_request_tenant(request)
    status_payload = await get_qr_session_status(tenant=tenant, qr_token=qr_token)
    if status_payload["status"] != qr_services.QR_STATUS_APPROVED:
        return QRStatusResponse(**status_payload)

    user = await claim_approved_qr_user(tenant=tenant, qr_token=qr_token)
    from .services.login_flow import activate_user_if_eligible

    is_active = await activate_user_if_eligible(
        user=user,
        tenant=tenant,
        login_request=LoginRequest(
            type=AuthIdentifier.QR_SESSION,
            identifier=user.uid,
            method=AuthSecret.MAGIC_LINK,
        ),
    )
    login_flow_result = LoginFlowResult(
        status=(
            LoginStatus.COMPLETED if is_active else LoginStatus.VERIFICATION_REQUIRED
        ),
        user=user,
        amr=["qr"],
    )
    payloads = await create_token_response(
        user=user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=get_client_ip(request),
        url=request.url,
    )
    maybe_attach_secure_token(
        payloads=payloads,
        user=user,
        tenant=tenant,
        status=login_flow_result.status,
        amr=login_flow_result.amr,
    )
    return await build_browser_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        next_step=None,
    )


@router_limited.post("/qr")
async def qr_approve(
    request: Request,
    data: QRApproveRequest,
    _: None = Depends(get_rate_limiter("/auth/qr")),
) -> dict[str, str]:
    """Approve or deny a pending QR session from an authenticated phone session."""
    from apps.identity.user.models import User

    tenant = await get_request_tenant(request)
    user_data = tenant.access_auth(request)
    user = await User.get_item(uid=user_data.uid, tenant_id=tenant.uid)
    if not user:
        raise UnauthorizedError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )
    return await approve_qr_session(
        tenant=tenant,
        user=user,
        qr_token=data.qr_token,
        approve=data.approve,
    )


@router_captchaed.post("/request-otp")
async def request_otp(
    request: Request,
    data: OTPRequest,
    _: None = Depends(get_rate_limiter("/auth/request-otp")),
    __: Response = Depends(check_captcha),
) -> Response:
    """Request OTP."""
    tenant = await get_request_tenant(request)

    origin = request.headers.get("origin")
    origin = sanitize_origin(origin)
    try:
        await create_otp(otp_request=data, tenant=tenant, origin=origin)
    except UnauthorizedError as exc:
        # Match the success response for unknown and existing identifiers.
        if exc.error_code != "registration_closed":
            raise

    return {"status": "success"}


@router_limited.post("/secure-token", response_model=LoginResponse)
async def issue_secure_token(
    request: Request,
    data: SecureTokenRequest,
) -> Response:
    """
    Issue a secure session token for a logged-in user after a secure step-up.

    Requires a valid access session. The submitted method must be a secure
    auth method (OTP / TOTP / magic-link / passkey). Does not create a new
    login session — only attaches ``usso-secure-token``.
    """
    from usso.user import TokenType

    from ..user.services import authenticate_user, find_user
    from .services.token import (
        attach_auth_cookies_to_response,
        is_cookie_auth_preferred,
    )

    tenant = await get_request_tenant(request)
    access_user = tenant.access_auth(request)
    if access_user is None:
        raise UnauthorizedError(
            error_code="authentication_required",
            detail="Authentication required",
            message={
                "en": "You must be signed in.",
                "fa": "برای این کار باید وارد شوید.",
            },
        )

    if not is_secure_method(data.method):
        raise BadRequestError(
            error_code="secure_method_required",
            detail="A secure authentication method is required",
            message={
                "en": "Use OTP, TOTP, magic link, or passkey to get a secure token.",
                "fa": (
                    "برای تأیید امن از رمز یک‌بارمصرف، لینک ورود "
                    "یا کلید عبور استفاده کنید."
                ),
            },
        )

    user = await find_user(
        identifier=data,
        tenant_id=tenant.uid,
        tenant=tenant,
    )
    if user is None or user.uid != access_user.uid:
        raise UnauthorizedError(
            error_code="secure_step_up_failed",
            detail="Secure step-up failed",
            message={
                "en": "Secure verification failed for this account.",
                "fa": "تأیید امن برای این حساب انجام نشد.",
            },
        )
    if not data.secret or not await authenticate_user(user=user, secret=data):
        raise UnauthorizedError(
            error_code="invalid_credentials",
            detail="Invalid credentials",
            message={
                "en": "Invalid credentials.",
                "fa": "اطلاعات ورود نادرست است.",
            },
        )

    amr = [data.method.value] if data.method else []
    secure_payload = create_secure_token_payload(
        user=user,
        tenant=tenant,
        amr=amr,
    )
    payloads = {TokenType.SECURE_TOKEN: secure_payload}

    from fastapi.responses import JSONResponse

    prefer_cookie = is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    )
    tokens = None if prefer_cookie else {TokenType.SECURE_TOKEN: secure_payload.token}
    body = LoginResponse(
        **secure_payload.model_dump(exclude={"token"}),
        status=LoginStatus.COMPLETED,
        tokens=tokens,
    )
    response = JSONResponse(content=body.model_dump(exclude_none=True))
    if prefer_cookie:
        attach_auth_cookies_to_response(
            response=response,
            tenant=tenant,
            payloads=payloads,
            domain=request.url.hostname,
        )
    return response


@router_limited.get("/secure-token/status")
async def secure_token_status(request: Request) -> dict:
    """
    Report whether the caller has a valid secure session token.

    Used by clients to unlock sensitive profile actions without forcing an
    OTP step-up when the user already signed in via a secure method.
    """
    tenant = await get_request_tenant(request)
    access_user = tenant.access_auth(request)
    if access_user is None:
        raise UnauthorizedError(
            error_code="authentication_required",
            detail="Authentication required",
            message={
                "en": "You must be signed in.",
                "fa": "برای این کار باید وارد شوید.",
            },
        )

    if not extract_secure_token(request):
        return {"valid": False}

    try:
        payload = require_secure_token(
            request=request,
            tenant=tenant,
            user_id=access_user.uid,
        )
    except UnauthorizedError:
        return {"valid": False}

    return {"valid": True, "exp": payload.exp}


@router_limited.post("/password")
async def set_password(
    request: Request,
    data: ResetPasswordRequest,
) -> dict:
    """
    Set or change the password using a valid secure session token.

    Forgot-password flow: complete a secure login (OTP/magic-link), then call
    this endpoint. Logged-in users: call ``POST /auth/secure-token`` first.
    """
    from utils.hasher import PasswordHasherService

    from ..session.models import AuthSession
    from ..user.models import Credential, User
    from .pass_validator import validate_password_policy

    tenant = await get_request_tenant(request)
    secure = require_secure_token(request=request, tenant=tenant)
    user = await User.get_item(uid=secure.sub, tenant_id=tenant.uid)
    if user is None:
        raise UnauthorizedError(
            error_code="secure_token_invalid",
            detail="Invalid or expired secure token",
            message={
                "en": "Secure token is invalid or expired.",
                "fa": "تأیید امن نامعتبر یا منقضی است.",
            },
        )

    policy_result = validate_password_policy(data.new_password, tenant.config.auth)
    if not policy_result.is_valid:
        raise BadRequestError(
            error_code="password_policy",
            detail=policy_result.unmet_requirements[0],
            message={
                "en": "Password does not meet policy requirements",
                "fa": "رمز عبور شرایط لازم را ندارد.",
            },
        )

    hashed_password = PasswordHasherService().hash_password(data.new_password)
    password_credentials = await Credential.get_query(
        tenant_id=tenant.uid,
        user_id=user.uid,
        method=AuthSecret.PASSWORD,
        is_deleted=False,
        is_active=True,
    ).to_list()

    if password_credentials:
        credential = password_credentials[0]
        credential.secret = hashed_password
        await credential.save()
    else:
        credential = Credential(
            tenant_id=tenant.uid,
            user_id=user.uid,
            method=AuthSecret.PASSWORD,
            secret=hashed_password,
            is_active=True,
        )
        await credential.save()

    # Password recovery must terminate every refreshable session. Existing
    # access JWTs naturally expire at the short access-token TTL.
    await AuthSession.revoke_user_sessions(
        tenant_id=tenant.uid,
        user_id=user.uid,
    )

    return {
        "status": "success",
        "message": "رمز عبور با موفقیت تغییر کرد.",
    }


@router_limited.post("/telegram", response_model=LoginResponse)
async def login_by_telegram(
    request: Request,
    data: TelegramIdTokenSchema,
) -> LoginResponse:
    """
    Authenticate via Telegram Login OIDC ``id_token``.

    Used by the Telegram Login JS SDK callback. Configure
    ``tenant.secrets.oauth_secrets.telegram`` (client_id + client_secret;
    discovery defaults to oauth.telegram.org). Prefer
    ``GET /auth/oauth/telegram/authorize`` for full redirect + PKCE flow.
    """
    from .services.oauth import _validated_oidc_endpoint, fetch_oidc_config
    from .services.telegram import (
        TELEGRAM_OIDC_DISCOVERY_URL,
        ensure_telegram_discovery,
    )

    tenant = await get_request_tenant(request)
    oauth_secret = require_telegram_oauth(tenant)
    oauth_secret = ensure_telegram_discovery(oauth_secret)
    discovery_url = oauth_secret.discovery_url or TELEGRAM_OIDC_DISCOVERY_URL
    oidc_config = await fetch_oidc_config(discovery_url)
    jwks_uri = await _validated_oidc_endpoint(oidc_config, "jwks_uri")
    claims = verify_telegram_id_token(
        id_token=data.id_token,
        client_id=oauth_secret.client_id,
        jwks_uri=jwks_uri,
    )
    telegram_user_id = telegram_user_id_from_claims(claims)
    login_request = build_telegram_login_request(
        telegram_user_id=telegram_user_id,
        id_token=data.id_token,
    )
    display_name = telegram_display_name(claims)
    kwargs: dict[str, object] = {"telegram_verified": True}
    if display_name:
        kwargs["name"] = display_name

    temporary_payload = tenant.temporary_auth(request)
    login_flow_result = await process_login_flow(
        login_request=login_request,
        tenant=tenant,
        temporary_payload=temporary_payload,
        **kwargs,
    )

    client_ip = get_client_ip(request)
    payloads = await create_token_response(
        user=login_flow_result.user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=client_ip,
        url=request.url,
    )
    maybe_attach_secure_token(
        payloads=payloads,
        user=login_flow_result.user,
        tenant=tenant,
        status=login_flow_result.status,
        amr=login_flow_result.amr,
    )
    return await build_browser_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        next_step=login_flow_result.next_step,
    )


@router_limited.get("/oauth/{provider}/authorize")
async def oauth_authorize(
    request: Request, provider: str, return_url: str | None = None
) -> Response:
    """OAuth authorize."""
    tenant = await get_request_tenant(request)

    if provider not in tenant.secrets.oauth_secrets:
        raise BadRequestError(
            error_code="invalid_provider",
            detail="Invalid OAuth provider",
            message={
                "en": "Invalid OAuth provider",
                "fa": "سرویس ورود انتخاب‌شده معتبر نیست.",
            },
        )

    session = await create_oauth_session(
        tenant=tenant, provider=provider, url=request.url
    )

    safe_return_url = sanitize_return_url(
        return_url or tenant.config.default_redirect_url,
        tenant,
    )

    response = RedirectResponse(session.authorization_url)
    response.set_cookie(
        "usso_oidc_state",
        session.state,
        httponly=True,
        secure=True,
        max_age=300,
        samesite="lax",
    )
    if session.code_verifier:
        response.set_cookie(
            "usso_oidc_verifier",
            session.code_verifier,
            httponly=True,
            secure=True,
            max_age=300,
            samesite="lax",
        )
    if session.nonce:
        response.set_cookie(
            "usso_oidc_nonce",
            session.nonce,
            httponly=True,
            secure=True,
            max_age=300,
            samesite="lax",
        )
    if safe_return_url:
        response.set_cookie(
            "usso_oauth_return_url",
            safe_return_url,
            httponly=True,
            secure=True,
            max_age=300,
            samesite="lax",
        )
    return response


@router_limited.get("/oauth/{provider}/callback")
async def oauth_callback(
    request: Request,
    response: Response,
    provider: str,
    state: str,
    code: str,
) -> Response:
    """OAuth callback."""
    tenant = await get_request_tenant(request)

    if provider not in tenant.secrets.oauth_secrets:
        raise BadRequestError(
            error_code="invalid_provider",
            detail="Invalid OAuth provider",
            message={
                "en": "Invalid OAuth provider",
                "fa": "سرویس ورود انتخاب‌شده معتبر نیست.",
            },
        )

    state_from_cookie = request.cookies.get("usso_oidc_state")
    if not state_from_cookie or state != state_from_cookie:
        raise BadRequestError(
            error_code="invalid_state",
            detail="Invalid or missing OAuth state parameter.",
            message={
                "en": "Invalid login request. Please sign in again from the start.",
                "fa": "درخواست ورود نامعتبر است. دوباره از ابتدا وارد شوید.",
            },
        )

    code_verifier = request.cookies.get("usso_oidc_verifier")
    expected_nonce = request.cookies.get("usso_oidc_nonce")
    if not expected_nonce:
        raise BadRequestError(
            error_code="invalid_nonce",
            detail="Missing OIDC nonce cookie",
        )
    id_token, userinfo, jwks_uri = await exchange_oauth_code_for_userinfo(
        code=code,
        tenant=tenant,
        provider=provider,
        url=request.url,
        code_verifier=code_verifier,
        expected_nonce=expected_nonce,
    )

    identity = _resolve_oauth_callback_identity(
        provider=provider,
        userinfo=userinfo,
        secrets_data=tenant.secrets.oauth_secrets.get(provider),
    )

    await create_oauth_credential(
        tenant=tenant,
        provider=provider,
        identifier=identity.identifier,
        identifier_type=identity.identifier_type,
        method=identity.method,
        jwks_uri=jwks_uri,
        userinfo=userinfo,
    )

    login_request = LoginRequest(
        type=identity.identifier_type,
        identifier=identity.identifier,
        method=identity.method,
        secret=id_token,
    )
    login_kwargs: dict[str, object] = {}
    if identity.method == AuthSecret.TELEGRAM_TOKEN:
        login_kwargs["telegram_verified"] = True
    elif identity.method == AuthSecret.OAUTH:
        login_kwargs["oauth_verified"] = True
    if identity.name:
        login_kwargs["name"] = identity.name

    temporary_payload = tenant.temporary_auth(request)
    login_flow_result = await process_login_flow(
        login_request=login_request,
        tenant=tenant,
        temporary_payload=temporary_payload,
        **login_kwargs,
    )
    client_ip = get_client_ip(request)
    payloads = await create_token_response(
        user=login_flow_result.user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=client_ip,
        url=request.url,
    )
    maybe_attach_secure_token(
        payloads=payloads,
        user=login_flow_result.user,
        tenant=tenant,
        status=login_flow_result.status,
        amr=login_flow_result.amr,
    )
    login_response = await build_browser_login_response(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        next_step=login_flow_result.next_step,
    )

    redirect_url = sanitize_return_url(
        request.cookies.get("usso_oauth_return_url"), tenant
    ) or sanitize_return_url(tenant.config.default_redirect_url, tenant)

    final_response: Response
    if redirect_url:
        final_response = RedirectResponse(redirect_url)
        for header, value in login_response.raw_headers:
            if header.lower() == b"set-cookie":
                final_response.raw_headers.append((header, value))
    else:
        final_response = login_response

    final_response.delete_cookie("usso_oidc_state")
    final_response.delete_cookie("usso_oidc_verifier")
    final_response.delete_cookie("usso_oidc_nonce")
    final_response.delete_cookie("usso_oauth_return_url")
    return final_response


@router_limited.post("/verify-token", response_model=PayloadData)
async def verify_token(request: Request, data: VerifyTokenRequest) -> PayloadData:
    """Verify token."""
    tenant = await get_request_tenant(request)

    usso_auth = tenant.get_auth(data.token_type)
    payload = usso_auth.user_data_from_token(
        data.token, expected_token_type=data.token_type
    )
    return payload


router.include_router(router_captchaed)
router.include_router(router_limited)


@router.get("/me", response_model=PayloadData)
async def me(request: Request) -> PayloadData:
    """Get current user info."""
    tenant = await get_request_tenant(request)

    usso_auth = tenant.get_auth("access")
    payload = usso_auth(request)
    return payload
