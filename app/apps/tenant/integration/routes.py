"""
OAuth2/OIDC routes for tenant integration.

This module contains FastAPI routes for OAuth2 and OpenID Connect
authorization server functionality.
"""

import base64
import logging
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request, status
from fastapi.responses import RedirectResponse
from fastapi_mongo_base.utils import timezone
from usso import UserData

from apps.identity.auth.services import require_secure_token
from apps.tenant.models import Tenant
from apps.tenant.services import get_tenant
from server.config import Settings
from server.exceptions import (
    BadRequestError,
    BaseHTTPException,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from server.rate_limiter import get_rate_limiter
from utils.hasher import PasswordHasherService

from . import dependencies
from .client_management import (
    deactivate_oauth_client,
    get_oauth_client,
    list_oauth_clients,
    regenerate_client_secret,
    update_oauth_client,
)
from .models import OAuthClient, OAuthSession
from .schemas import (
    AuthorizationRequestSchema,
    ClientRegistrationRequestSchema,
    ClientRegistrationResponseSchema,
    ClientUpdateSchema,
    GrantType,
    OuathDeviceAuthorizationDecisionSchema,
    OuathDeviceAuthorizationInfoSchema,
    OuathDeviceAuthorizationResponseSchema,
    ResponseType,
    TokenIntrospectionResponseSchema,
    TokenRequestSchema,
    TokenResponseSchema,
    UserInfoResponseSchema,
)
from .services import (
    consume_oauth_consent,
    create_authorization_code,
    create_tokens,
    exchange_authorization_code,
    exchange_service_account_client_credentials,
    get_user_info,
    introspect_token,
    refresh_access_token,
    register_client,
    revoke_token,
    validate_authorization_request,
    validate_client,
    verify_oauth_client_secret,
)

logger = logging.getLogger(__name__)

oidc_auth_router = APIRouter(tags=["OIDC-Auth"])
oidc_client_router = APIRouter(prefix="/clients", tags=["OIDC-Client"])


def _redirect_with_params(url: str, params: dict[str, str]) -> str:
    """Append OAuth response parameters without discarding a registered query."""
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params)}"


def _require_oauth_client_authentication(
    *,
    client: OAuthClient,
    client_secret: str | None,
    presented_auth_method: str,
) -> None:
    """Enforce the registered token-endpoint authentication method."""
    if client.token_endpoint_auth_method != presented_auth_method:
        raise UnauthorizedError(
            error_code="invalid_client",
            detail="Client authentication method is not allowed",
        )
    if not verify_oauth_client_secret(client, client_secret):
        raise UnauthorizedError(
            error_code="invalid_client",
            detail="Invalid client credentials",
            message={
                "en": "Invalid client credentials",
                "fa": "اطلاعات ابزار نامعتبر است.",
            },
        )


async def _handle_authorized_user(
    client: OAuthClient,
    current_user: UserData,
    tenant: Tenant,
    response_type: ResponseType,
    redirect_uri: str,
    valid_scopes: list[str],
    nonce: str | None,
    state: str | None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> RedirectResponse:
    """Handle authorization for already authenticated user."""
    auth_code = await create_authorization_code(
        client=client,
        user=current_user,
        tenant=tenant,
        redirect_uri=redirect_uri,
        scope=valid_scopes,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    response_params = {"code": auth_code.code}
    if state:
        response_params["state"] = state
    return RedirectResponse(_redirect_with_params(redirect_uri, response_params))


@oidc_auth_router.get("/authorize")
async def authorize(
    request: Request,
    response_type: ResponseType = Query(..., description="Response type"),
    client_id: str = Query(..., description="Client identifier"),
    redirect_uri: str = Query(..., description="Redirect URI"),
    scope: str | None = Query(None, description="Requested scopes"),
    state: str = Query(..., min_length=16, description="CSRF state parameter"),
    code_challenge: str | None = Query(None, description="PKCE code challenge"),
    code_challenge_method: str | None = Query(
        "S256", description="PKCE code challenge method"
    ),
    nonce: str | None = Query(None, description="Nonce for ID token"),
    prompt: str | None = Query(None, description="Prompt parameter"),
    max_age: int | None = Query(None, description="Maximum authentication age"),
) -> RedirectResponse:
    """OAuth2 Authorization endpoint."""
    tenant = await get_tenant(request)

    auth_request = AuthorizationRequestSchema(
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        prompt=prompt,
        max_age=max_age,
    )

    try:
        client, valid_scopes = await validate_authorization_request(
            auth_request, tenant
        )

        current_user = await dependencies.get_current_user_optional(request)
        if not current_user:
            login_url = tenant.get_frontend_url("login")
            # set query param to redirect to current url with query params
            params = {"redirect_to": str(request.url)}
            return RedirectResponse(
                f"{login_url}?{urlencode(params)}",
                # status_code=status.HTTP_302_FOUND,  # ruff:ignore[commented-out-code]
            )

        session = await OAuthSession.get_by_state(state, tenant.uid) if state else None
        if session and (
            session.user_id != current_user.uid
            or session.client_id != client.client_id
            or session.redirect_uri != redirect_uri
            or list(session.scope) != valid_scopes
            or getattr(session, "nonce", None) != nonce
            or getattr(session, "code_challenge", None) != code_challenge
            or getattr(session, "code_challenge_method", None) != code_challenge_method
        ):
            raise BadRequestError(
                error_code="invalid_oauth_session",
                detail="OAuth session binding mismatch",
                message={"en": "Invalid OAuth session", "fa": "نشست ورود نامعتبر است."},
            )
        if session and (session.is_consented or getattr(session, "is_consumed", False)):
            raise BadRequestError(
                error_code="oauth_session_replayed",
                detail="OAuth consent session has already been consumed",
            )

        if not session:
            session = OAuthSession.create_session(
                client_id=client_id,
                user_id=current_user.uid,
                tenant_id=tenant.uid,
                scope=valid_scopes,
                redirect_uri=redirect_uri,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
            await session.save()

        consent_url = f"{tenant.primary_url}{Settings.base_path}/oauth/consent"
        params = {
            "client_id": client_id,
            "scope": " ".join(valid_scopes),
            "state": state or "",
        }
        consent_params = {
            "client_id": client_id,
            "client_name": client.client_name,
            "scope": " ".join(valid_scopes),
            "redirect_uri": f"{consent_url}?{urlencode(params | {'consent': 'true'})}",
        }

    except BaseHTTPException as e:
        logger.exception("Authorization failed")
        error_params = {"error": "invalid_request", "error_description": str(e.detail)}
        if state:
            error_params["state"] = state
        # Proper OAuth2 error response - redirect with error parameters
        return RedirectResponse(
            f"{tenant.get_frontend_url('oauth_authorize')}?{urlencode(error_params)}",
            # status_code=status.HTTP_302_FOUND,  # ruff:ignore[commented-out-code]
        )

    consent_url = f"{tenant.get_frontend_url('consent')}?{urlencode(consent_params)}"
    logger.info("Redirecting to consent UI for client %s", client.client_id)
    return RedirectResponse(consent_url)
    {
        "consent_url": consent_url,
        "params": params,
        "client_name": client.client_name,
        "redirect_uri": f"{consent_url}?{urlencode(params | {'consent': 'true'})}",
    }


@oidc_auth_router.post("/consent")
async def consent_authorize(
    request: Request,
    state: str = Query("", description="State parameter"),
    consent: bool = Query(..., description="User consent"),
) -> RedirectResponse:
    """OAuth2 Consent endpoint."""
    tenant = await get_tenant(request)
    current_user = await dependencies.get_current_user(request)
    session: OAuthSession | None = None

    try:
        # Get session
        session = await OAuthSession.get_by_state(state, tenant.uid)
        if (
            not session
            or session.user_id != current_user.uid
            or session.is_consented
            or getattr(session, "is_consumed", False)
            or (
                session.created_at.replace(tzinfo=timezone.tz)
                < datetime.now(timezone.tz) - timedelta(minutes=10)
            )
            or session.is_expired()
        ):
            return RedirectResponse(
                f"{tenant.get_frontend_url('oauth_failed')}?"
                + urlencode({
                    "error": "access_denied",
                    "error_description": "Invalid session",
                }),
            )

        # Get current user
        client = await validate_client(session.client_id, tenant)
        if not client:
            return RedirectResponse(
                tenant.get_frontend_url("oauth_failed"),
                status_code=status.HTTP_303,
            )

        if not consent:
            # User denied consent
            consumed = await consume_oauth_consent(
                session,
                granted_scope=[],
                consented=False,
            )
            if not consumed:
                return RedirectResponse(
                    f"{tenant.get_frontend_url('oauth_failed')}?"
                    + urlencode({
                        "error": "access_denied",
                        "error_description": "Invalid session",
                    }),
                )
            error_params = {
                "error": "access_denied",
                "error_description": "User denied the request",
            }
            if state:
                error_params["state"] = state

            return RedirectResponse(
                _redirect_with_params(session.redirect_uri, error_params),
                status_code=status.HTTP_302_FOUND,
            )

        # User granted consent
        granted_scopes = [s.strip() for s in session.scope if s.strip()]
        consumed = await consume_oauth_consent(
            session,
            granted_scope=granted_scopes,
            consented=True,
        )
        if not consumed:
            return RedirectResponse(
                f"{tenant.get_frontend_url('oauth_failed')}?"
                + urlencode({
                    "error": "access_denied",
                    "error_description": "Invalid session",
                }),
            )

        # Create authorization code
        auth_code = await create_authorization_code(
            client=client,
            user=current_user,
            tenant=tenant,
            redirect_uri=session.redirect_uri,
            scope=granted_scopes,
            nonce=session.nonce,
            code_challenge=getattr(session, "code_challenge", None),
            code_challenge_method=getattr(session, "code_challenge_method", None),
        )

    except BaseHTTPException as e:
        logger.exception("Consent failed")
        # Return error
        error_params = {
            "error": "server_error",
            "error_description": str(e.detail),
        }
        if state:
            error_params["state"] = state

        failure_url = (
            session.redirect_uri
            if session is not None
            else tenant.get_frontend_url("oauth_failed")
        )
        return RedirectResponse(
            _redirect_with_params(failure_url, error_params),
            status_code=status.HTTP_302_FOUND,
        )

    response_params = {"code": auth_code.code}
    if state:
        response_params["state"] = state

    consented_url = _redirect_with_params(session.redirect_uri, response_params)
    logger.info("Consent authorized for client %s", client.client_id)
    return RedirectResponse(consented_url, status_code=status.HTTP_302_FOUND)


@oidc_auth_router.post(
    "/device_authorization",
    response_model=OuathDeviceAuthorizationResponseSchema,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter("/oauth/device_authorization"))],
)
async def device_authorization(
    request: Request,
    client_id: str = Form(..., description="Client identifier"),
    scope: str | None = Form(None, description="Requested scopes"),
) -> OuathDeviceAuthorizationResponseSchema:
    """OAuth 2.0 Device Authorization endpoint (RFC 8628)."""
    from . import device_code as device_code_services

    tenant = await get_tenant(request)
    client = await validate_client(client_id, tenant)
    return await device_code_services.create_device_authorization(
        tenant=tenant,
        client=client,
        scope=scope,
    )


@oidc_auth_router.get(
    "/device",
    response_model=OuathDeviceAuthorizationInfoSchema,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter("/oauth/device"))],
)
async def get_device_authorization(
    request: Request,
    user_code: str = Query(..., description="User verification code"),
) -> OuathDeviceAuthorizationInfoSchema:
    """Look up a pending device authorization for the consent UI."""
    from datetime import datetime

    from fastapi_mongo_base.utils import timezone

    from . import device_code as device_code_services

    tenant = await get_tenant(request)
    await dependencies.get_current_user(request)
    auth = await device_code_services.get_pending_by_user_code(
        tenant_id=tenant.uid,
        user_code=user_code,
    )
    client = await validate_client(auth.client_id, tenant)
    expires_at = auth.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.tz)
    expires_in = max(0, int((expires_at - datetime.now(timezone.tz)).total_seconds()))
    return OuathDeviceAuthorizationInfoSchema(
        user_code=auth.user_code,
        client_id=auth.client_id,
        client_name=client.client_name,
        scope=auth.scope,
        expires_in=expires_in,
    )


@oidc_auth_router.post(
    "/device",
    response_model=OuathDeviceAuthorizationInfoSchema,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter("/oauth/device"))],
)
async def decide_device_authorization(
    request: Request,
    data: OuathDeviceAuthorizationDecisionSchema,
) -> OuathDeviceAuthorizationInfoSchema:
    """Approve or deny a pending device authorization (logged-in user)."""
    from datetime import datetime

    from fastapi_mongo_base.utils import timezone

    from . import device_code as device_code_services

    tenant = await get_tenant(request)
    current_user = await dependencies.get_current_user(request)
    auth = await device_code_services.approve_device_authorization(
        tenant=tenant,
        user=current_user,
        user_code=data.user_code,
        approve=data.approve,
        granted_scope=data.scope,
    )
    client = await validate_client(auth.client_id, tenant)
    expires_at = auth.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.tz)
    expires_in = max(0, int((expires_at - datetime.now(timezone.tz)).total_seconds()))
    return OuathDeviceAuthorizationInfoSchema(
        user_code=auth.user_code,
        client_id=auth.client_id,
        client_name=client.client_name,
        scope=auth.granted_scope or auth.scope,
        expires_in=expires_in,
    )


@oidc_auth_router.post(
    "/token",
    response_model=TokenResponseSchema,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter("/oauth/token"))],
)
async def token(
    request: Request,
    grant_type: GrantType = Form(..., description="Grant type"),
    client_id: str | None = Form(None, description="Client identifier"),
    client_secret: str | None = Form(None, description="Client secret"),
    code: str | None = Form(None, description="Authorization code"),
    redirect_uri: str | None = Form(None, description="Redirect URI"),
    code_verifier: str | None = Form(None, description="PKCE code verifier"),
    refresh_token: str | None = Form(None, description="Refresh token"),
    scope: str | None = Form(None, description="Requested scopes"),
    device_code: str | None = Form(None, description="Device code"),
) -> TokenResponseSchema:
    """OAuth2 Token endpoint."""
    from . import device_code as device_code_services

    tenant = await get_tenant(request)
    authorization = request.headers.get("authorization", "")
    presented_auth_method = "client_secret_post" if client_secret else "none"
    if authorization.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(authorization[6:], validate=True).decode()
            basic_client_id, basic_client_secret = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            raise UnauthorizedError(
                error_code="invalid_client",
                detail="Invalid client authentication",
                message={
                    "en": "Invalid client authentication",
                    "fa": "اطلاعات ابزار نامعتبر است.",
                },
            ) from None
        if client_id and client_id != basic_client_id:
            raise UnauthorizedError(
                error_code="invalid_client", detail="Conflicting client IDs"
            )
        client_id = basic_client_id
        client_secret = basic_client_secret
        presented_auth_method = "client_secret_basic"
    if client_id is None:
        client_id = (await request.form()).get("client_id")
        logger.warning("Client ID is None, %s", client_id)
    # Create token request schema from form data
    token_request = TokenRequestSchema(
        grant_type=grant_type,
        client_id=client_id,
        client_secret=client_secret,
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        refresh_token=refresh_token,
        scope=scope,
        device_code=device_code,
    )

    if token_request.grant_type == GrantType.CLIENT_CREDENTIALS:
        return await exchange_service_account_client_credentials(
            tenant=tenant,
            client_id=token_request.client_id or "",
            client_secret=token_request.client_secret,
            scope=token_request.scope,
        )

    if token_request.grant_type == GrantType.DEVICE_CODE:
        client = await validate_client(token_request.client_id, tenant)
        _require_oauth_client_authentication(
            client=client,
            client_secret=token_request.client_secret,
            presented_auth_method=presented_auth_method,
        )
        return await device_code_services.exchange_device_code(
            tenant=tenant,
            client_id=client.client_id,
            device_code=token_request.device_code or "",
        )

    # Validate OAuth client for interactive grants
    client = await validate_client(token_request.client_id, tenant)
    _require_oauth_client_authentication(
        client=client,
        client_secret=token_request.client_secret,
        presented_auth_method=presented_auth_method,
    )

    # Handle different grant types
    if token_request.grant_type == GrantType.AUTHORIZATION_CODE:
        # Authorization Code Grant
        user, scope, nonce = await exchange_authorization_code(
            code=token_request.code,
            client=client,
            tenant=tenant,
            redirect_uri=token_request.redirect_uri,
            code_verifier=token_request.code_verifier,
        )

        return await create_tokens(
            client=client,
            user=user,
            tenant=tenant,
            scope=scope,
            nonce=nonce,
        )

    elif token_request.grant_type == GrantType.REFRESH_TOKEN:
        # Refresh Token Grant
        return await refresh_access_token(
            refresh_token=token_request.refresh_token,
            client=client,
            tenant=tenant,
        )

    else:
        raise BadRequestError(
            error_code="unsupported_grant_type",
            detail="Unsupported grant type",
            message={
                "en": "Unsupported grant type",
                "fa": "این روش دریافت دسترسی پشتیبانی نمی‌شود.",
            },
        )


@oidc_auth_router.get(
    "/userinfo",
    response_model=UserInfoResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def userinfo(request: Request) -> UserInfoResponseSchema:
    """OpenID Connect UserInfo endpoint."""
    tenant = await get_tenant(request)

    authorization = request.headers.get("Authorization")

    # Extract access token from Authorization header
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError(
            error_code="invalid_authorization_header",
            detail="Invalid authorization header",
            message={
                "en": "Invalid authorization header",
                "fa": "اطلاعات ورود نامعتبر است.",
            },
        )

    access_token = authorization[7:]  # Remove "Bearer " prefix

    return await get_user_info(access_token, tenant)


@oidc_auth_router.post(
    "/introspect",
    response_model=TokenIntrospectionResponseSchema,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter("/oauth/introspect"))],
)
async def introspect(
    request: Request,
    token: str = Form(..., description="Token to introspect"),
    token_type_hint: str | None = Form(None, description="Token type hint"),
    client_id: str = Form(..., description="Client identifier"),
    client_secret: str | None = Form(None, description="Client secret"),
) -> TokenIntrospectionResponseSchema:
    """OAuth2 Token Introspection endpoint."""
    tenant = await get_tenant(request)

    # Validate client authentication
    client = await validate_client(client_id, tenant)

    # Verify client secret for confidential clients
    if not verify_oauth_client_secret(client, client_secret):
        raise UnauthorizedError(
            error_code="invalid_client",
            detail="Invalid client credentials",
            message={
                "en": "Invalid client credentials",
                "fa": "اطلاعات ابزار ورود جانبی نامعتبر است.",
            },
        )

    return await introspect_token(token, tenant)


@oidc_auth_router.post(
    "/revoke",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_rate_limiter("/oauth/revoke"))],
)
async def revoke(
    request: Request,
    token: str = Form(..., description="Token to revoke"),
    token_type_hint: str | None = Form(None, description="Token type hint"),
    client_id: str = Form(..., description="Client identifier"),
    client_secret: str | None = Form(None, description="Client secret"),
) -> dict[str, str]:
    """OAuth2 Token Revocation endpoint."""
    tenant = await get_tenant(request)

    # Validate client authentication
    client = await validate_client(client_id, tenant)

    # Verify client secret for confidential clients
    if not verify_oauth_client_secret(client, client_secret):
        raise UnauthorizedError(
            error_code="invalid_client",
            detail="Invalid client credentials",
            message={
                "en": "Invalid client credentials",
                "fa": "اطلاعات ابزار ورود جانبی نامعتبر است.",
            },
        )

    try:
        await revoke_token(token, client, tenant)
    except Exception as e:
        logger.exception("Token revocation failed")
        raise ServiceUnavailableError(
            error_code="server_error",
            detail="Token revocation failed",
            message={
                "en": "Token revocation failed",
                "fa": "لغو دسترسی انجام نشد.",
            },
        ) from e

    return {"status": "success"}


@oidc_client_router.post(
    "",
    response_model=ClientRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_client_endpoint(
    request: Request,
    registration_request: ClientRegistrationRequestSchema,
) -> ClientRegistrationResponseSchema:
    """OAuth2 Dynamic Client Registration endpoint."""
    tenant = await get_tenant(request)
    user = await dependencies.get_current_user(request)
    require_secure_token(request=request, tenant=tenant, user_id=user.uid)
    return await register_client(registration_request, tenant, user)


@oidc_client_router.get(
    "/{client_id}",
    response_model=ClientRegistrationResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def get_client(
    request: Request,
    client_id: str,
) -> ClientRegistrationResponseSchema:
    """Get OAuth2 client information (owner or registration_access_token)."""
    tenant = await get_tenant(request)
    user = await dependencies.get_current_user(request)

    client = await get_oauth_client(tenant, client_id)
    if not client:
        raise NotFoundError(
            detail="Client not found",
            message={"en": "Client not found", "fa": "ابزار ورود جانبی پیدا نشد."},
        )

    auth_header = request.headers.get("Authorization", "")
    rat = (
        auth_header.removeprefix("Bearer ").strip()
        if auth_header.startswith("Bearer ")
        else None
    )
    owns_client = client.user_id == user.uid
    has_rat = bool(
        rat
        and client.registration_access_token
        and PasswordHasherService().verify_password(
            client.registration_access_token, rat
        )
    )
    if not owns_client and not has_rat:
        raise ForbiddenError(
            error_code="client_access_denied",
            detail="Not allowed to retrieve this client",
            message={
                "en": "You do not have access to this OAuth client.",
                "fa": "به این ابزار ورود جانبی دسترسی ندارید.",
            },
        )

    return ClientRegistrationResponseSchema(
        client_id=client.client_id,
        client_secret="***",  # ruff:ignore[hardcoded-password-func-arg]
        client_name=client.client_name,
        client_type=client.client_type,
        redirect_uris=client.redirect_uris,
        allowed_scopes=client.allowed_scopes,
        grant_types=client.grant_types,
        response_types=client.response_types,
        logo_uri=client.logo_uri,
        client_uri=client.client_uri,
        policy_uri=client.policy_uri,
        tos_uri=client.tos_uri,
        require_pkce=client.require_pkce,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        is_active=client.is_active,
        client_id_issued_at=int(client.created_at.timestamp())
        if client.created_at
        else 0,
        client_secret_expires_at=0,
        registration_access_token="",
        registration_client_uri=f"{tenant.primary_url}{Settings.base_path}/oauth/clients/{client.client_id}",
    )


# REST Level 2 endpoints for client management
@oidc_client_router.get(
    "",
    response_model=list[ClientRegistrationResponseSchema],
    status_code=status.HTTP_200_OK,
)
async def list_clients(
    request: Request,
    is_active: bool | None = Query(None, description="Filter by active status"),
) -> list[ClientRegistrationResponseSchema]:
    """List OAuth2 clients (REST Level 2)."""
    tenant = await get_tenant(request)
    user = await dependencies.get_current_user(request)

    clients = await list_oauth_clients(
        tenant=tenant, user_id=user.uid, is_active=is_active
    )

    return [
        ClientRegistrationResponseSchema(
            client_id=client.client_id,
            client_secret="***",  # ruff:ignore[hardcoded-password-func-arg]
            client_name=client.client_name,
            client_type=client.client_type,
            redirect_uris=client.redirect_uris,
            allowed_scopes=client.allowed_scopes,
            grant_types=client.grant_types,
            response_types=client.response_types,
            logo_uri=client.logo_uri,
            client_uri=client.client_uri,
            policy_uri=client.policy_uri,
            tos_uri=client.tos_uri,
            require_pkce=client.require_pkce,
            token_endpoint_auth_method=client.token_endpoint_auth_method,
            is_active=client.is_active,
            client_id_issued_at=int(client.created_at.timestamp())
            if client.created_at
            else 0,
            client_secret_expires_at=0,
            registration_access_token="",
            registration_client_uri=f"{tenant.primary_url}{Settings.base_path}/oauth/clients/{client.client_id}",
        )
        for client in clients
    ]


@oidc_client_router.patch(
    "/{client_id}",
    response_model=ClientRegistrationResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def update_client(
    request: Request,
    client_id: str,
    update_data: ClientUpdateSchema,
) -> ClientRegistrationResponseSchema:
    """Update OAuth2 client (REST Level 2)."""
    tenant = await get_tenant(request)
    user = await dependencies.get_current_user(request)
    require_secure_token(request=request, tenant=tenant, user_id=user.uid)

    # Get client and verify ownership
    client = await get_oauth_client(tenant, client_id)
    if not client:
        raise NotFoundError(
            detail="Client not found",
            message={"en": "Client not found", "fa": "ابزار ورود جانبی پیدا نشد."},
        )

    # Verify user owns the client
    if client.user_id != user.uid:
        raise ForbiddenError(
            detail="You don't have permission to update this client",
            message={
                "en": "You don't have permission to update this client",
                "fa": "به ویرایش این ابزار ورود جانبی دسترسی ندارید.",
            },
        )

    # Prepare update data (exclude None values)
    update_dict = update_data.model_dump(exclude_unset=True, exclude_none=True)

    # Update client
    updated_client = await update_oauth_client(
        tenant=tenant, client_id=client_id, **update_dict
    )

    if not updated_client:
        raise ServiceUnavailableError(
            error_code="update_failed",
            detail="Failed to update client",
            message={
                "en": "Failed to update client",
                "fa": "ویرایش ابزار ورود جانبی انجام نشد.",
            },
        )

    return ClientRegistrationResponseSchema(
        client_id=updated_client.client_id,
        client_secret="***",  # ruff:ignore[hardcoded-password-func-arg]
        client_name=updated_client.client_name,
        client_type=updated_client.client_type,
        redirect_uris=updated_client.redirect_uris,
        allowed_scopes=updated_client.allowed_scopes,
        grant_types=updated_client.grant_types,
        response_types=updated_client.response_types,
        logo_uri=updated_client.logo_uri,
        client_uri=updated_client.client_uri,
        policy_uri=updated_client.policy_uri,
        tos_uri=updated_client.tos_uri,
        require_pkce=updated_client.require_pkce,
        token_endpoint_auth_method=updated_client.token_endpoint_auth_method,
        is_active=updated_client.is_active,
        client_id_issued_at=int(updated_client.created_at.timestamp())
        if updated_client.created_at
        else 0,
        client_secret_expires_at=0,
        registration_access_token="",
        registration_client_uri=f"{tenant.primary_url}{Settings.base_path}/oauth/clients/{updated_client.client_id}",
    )


@oidc_client_router.delete(
    "/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(
    request: Request,
    client_id: str,
) -> None:
    """Delete/deactivate OAuth2 client (REST Level 2)."""
    tenant = await get_tenant(request)
    user = await dependencies.get_current_user(request)
    require_secure_token(request=request, tenant=tenant, user_id=user.uid)

    # Get client and verify ownership
    client = await get_oauth_client(tenant, client_id)
    if not client:
        raise NotFoundError(
            detail="Client not found",
            message={"en": "Client not found", "fa": "ابزار ورود جانبی پیدا نشد."},
        )

    # Verify user owns the client
    if client.user_id != user.uid:
        raise ForbiddenError(
            detail="You don't have permission to delete this client",
            message={
                "en": "You don't have permission to delete this client",
                "fa": "به حذف این ابزار ورود جانبی دسترسی ندارید.",
            },
        )

    # Deactivate client (soft delete)
    success = await deactivate_oauth_client(tenant=tenant, client_id=client_id)
    if not success:
        raise ServiceUnavailableError(
            error_code="delete_failed",
            detail="Failed to delete client",
            message={
                "en": "Failed to delete client",
                "fa": "حذف ابزار ورود جانبی انجام نشد.",
            },
        )


@oidc_client_router.post(
    "/{client_id}/rotate-secret",
    status_code=status.HTTP_200_OK,
)
async def rotate_client_secret(
    request: Request,
    client_id: str,
) -> dict[str, str]:
    """Rotate OAuth2 client secret (REST Level 2)."""
    tenant = await get_tenant(request)
    user = await dependencies.get_current_user(request)
    require_secure_token(request=request, tenant=tenant, user_id=user.uid)

    # Get client and verify ownership
    client = await get_oauth_client(tenant, client_id)
    if not client:
        raise NotFoundError(
            detail="Client not found",
            message={"en": "Client not found", "fa": "ابزار ورود جانبی پیدا نشد."},
        )

    # Verify user owns the client
    if client.user_id != user.uid:
        raise ForbiddenError(
            detail="You don't have permission to rotate this client's secret",
            message={
                "en": "You don't have permission to rotate this client's secret",
                "fa": "به تغییر رمز این ابزار ورود جانبی دسترسی ندارید.",
            },
        )

    # Rotate secret
    new_secret = await regenerate_client_secret(tenant=tenant, client_id=client_id)
    if not new_secret:
        raise ServiceUnavailableError(
            error_code="rotate_failed",
            detail="Failed to rotate client secret",
            message={
                "en": "Failed to rotate client secret",
                "fa": "تغییر رمز ابزار ورود جانبی انجام نشد.",
            },
        )

    return {
        "client_id": client_id,
        "client_secret": new_secret,
        "message": "Client secret rotated successfully",
    }


router = APIRouter(prefix=f"{Settings.base_path}/oauth")
router.include_router(oidc_auth_router)
router.include_router(oidc_client_router)
