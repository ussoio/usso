"""
OAuth2/OIDC services for tenant integration.

This module contains business logic for OAuth2 and OpenID Connect
authorization server functionality.
"""

import base64
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta

from fastapi_mongo_base.utils import timezone

from apps.identity.user.models import User
from apps.tenant.models import Tenant
from server.exceptions import BadRequestError, UnauthorizedError
from utils.hasher import PasswordHasherService

from .client_management import get_oauth_client
from .models import AuthorizationCode, OAuthClient, OAuthSession, OAuthToken
from .schemas import (
    AuthorizationRequestSchema,
    ClientRegistrationRequestSchema,
    ClientRegistrationResponseSchema,
    Scope,
    TokenIntrospectionResponseSchema,
    TokenResponseSchema,
    UserInfoResponseSchema,
)


async def validate_client(
    client_id: str, tenant: Tenant, redirect_uri: str | None = None
) -> OAuthClient:
    """Validate OAuth client and return client instance."""
    client = await get_oauth_client(tenant, client_id)

    if not client:
        raise BadRequestError(
            error_code="invalid_client_id",
            detail="Invalid client_id",
            message={
                "en": "Invalid client_id",
                "fa": "شناسه ابزار ورود جانبی نامعتبر است.",
            },
        )

    if not client.is_active:
        raise BadRequestError(
            error_code="client_not_active",
            detail="Client is not active",
            message={
                "en": "Client is not active",
                "fa": "این ابزار ورود جانبی غیرفعال است.",
            },
        )

    if redirect_uri and redirect_uri not in client.redirect_uris:
        raise BadRequestError(
            error_code="invalid_redirect_uri",
            detail="Invalid redirect_uri",
            message={
                "en": "Invalid redirect_uri",
                "fa": "آدرس بازگشت نامعتبر است.",
            },
        )

    return client


async def validate_authorization_request(
    request: AuthorizationRequestSchema, tenant: Tenant
) -> tuple[OAuthClient, list[str]]:
    """Validate authorization request and return client and scopes."""
    # Validate client
    client = await validate_client(request.client_id, tenant, request.redirect_uri)

    # Validate response type
    if request.response_type not in client.response_types:
        raise BadRequestError(
            error_code="unsupported_response_type",
            detail="Unsupported response_type",
            message={
                "en": "Unsupported response_type",
                "fa": "نوع پاسخ درخواستی پشتیبانی نمی‌شود.",
            },
        )

    if request.code_challenge_method not in {None, "S256"}:
        raise BadRequestError(
            error_code="invalid_code_challenge_method",
            detail="Only PKCE S256 is supported",
            message={
                "en": "Only PKCE S256 is supported",
                "fa": "روش PKCE نامعتبر است.",
            },
        )
    if not request.code_challenge:
        raise BadRequestError(
            error_code="code_challenge_required",
            detail="PKCE code_challenge is required for this client",
            message={
                "en": "PKCE code_challenge is required for this client",
                "fa": "اطلاعات PKCE برای این ابزار الزامی است.",
            },
        )

    # Parse and validate scopes
    requested_scopes = request.scope or []
    if isinstance(requested_scopes, str):
        requested_scopes = [s.strip() for s in requested_scopes.split() if s.strip()]

    # Filter scopes based on client allowed scopes
    allowed_scopes = [scope.value for scope in client.allowed_scopes]
    valid_scopes = [scope for scope in requested_scopes if scope in allowed_scopes]

    if not valid_scopes:
        valid_scopes = [Scope.OPENID.value]  # Default scope

    return client, valid_scopes


async def create_authorization_code(
    client: OAuthClient,
    user: User,
    tenant: Tenant,
    redirect_uri: str,
    scope: list[str],
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> AuthorizationCode:
    """Create authorization code."""
    # Revoke any existing codes for this client/user combination
    existing_codes = await AuthorizationCode.find({
        "client_id": client.client_id,
        "user_id": user.uid,
        "tenant_id": tenant.uid,
        "is_used": False,
    }).to_list()

    for code in existing_codes:
        code.is_used = True
        await code.save()

    # Create new authorization code
    auth_code = AuthorizationCode.create_code(
        client_id=client.client_id,
        user_id=user.uid,
        tenant_id=tenant.uid,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    await auth_code.save()
    return auth_code


def _validate_pkce(auth_code: AuthorizationCode, code_verifier: str | None) -> None:
    """Validate PKCE code challenge."""
    if not auth_code.code_challenge:
        return

    if not code_verifier:
        raise BadRequestError(
            error_code="code_verifier_required",
            detail="code_verifier is required",
            message={
                "en": "code_verifier is required",
                "fa": "اطلاعات تأیید ورود ناقص است.",
            },
        )

    if auth_code.code_challenge_method == "S256":
        # Correct PKCE S256 implementation
        code_verifier_bytes = code_verifier.encode("ascii")
        digest = hashlib.sha256(code_verifier_bytes).digest()
        expected_challenge = (
            base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        )
        if auth_code.code_challenge != expected_challenge:
            raise BadRequestError(
                error_code="invalid_code_verifier",
                detail="Invalid code_verifier",
                message={
                    "en": "Invalid code_verifier",
                    "fa": "اطلاعات تأیید ورود نامعتبر است.",
                },
            )
    else:
        raise BadRequestError(
            error_code="invalid_code_challenge_method",
            detail="Only PKCE S256 is supported",
            message={
                "en": "Only PKCE S256 is supported",
                "fa": "روش PKCE نامعتبر است.",
            },
        )


def verify_oauth_client_secret(client: OAuthClient, client_secret: str | None) -> bool:
    """Verify a confidential OAuth client's secret in constant time."""
    if client.client_type != "confidential":
        return True
    if not client_secret:
        return False
    # PasswordHasherService accepts only salted password-hash formats. Legacy
    # plaintext values deliberately fail closed and must be rotated by the owner.
    return PasswordHasherService().verify_password(
        client.client_secret,
        client_secret,
    )


async def consume_oauth_consent(
    session: OAuthSession,
    *,
    granted_scope: list[str],
    consented: bool,
) -> bool:
    """Atomically finalize one OAuth consent decision and prevent replay."""
    result = await OAuthSession.get_pymongo_collection().update_one(
        {
            "uid": session.uid,
            "tenant_id": session.tenant_id,
            "user_id": session.user_id,
            "is_consented": False,
            "is_consumed": {"$ne": True},
            "expires_at": {"$gt": datetime.now(timezone.tz)},
        },
        {
            "$set": {
                "is_consented": consented,
                "is_consumed": True,
                "granted_scope": granted_scope if consented else [],
            }
        },
    )
    if result.modified_count != 1:
        return False
    session.is_consented = consented
    session.is_consumed = True
    session.granted_scope = granted_scope if consented else []
    return True


async def exchange_authorization_code(
    code: str,
    client: OAuthClient,
    tenant: Tenant,
    redirect_uri: str,
    code_verifier: str | None = None,
) -> tuple[User, list[str], str | None]:
    """Exchange authorization code for user, scopes, and nonce."""
    auth_code = await AuthorizationCode.get_by_code(code, tenant.uid)

    if not auth_code:
        raise BadRequestError(
            error_code="invalid_authorization_code",
            detail="Invalid authorization code",
            message={
                "en": "Invalid authorization code",
                "fa": "کد تأیید ورود نامعتبر است.",
            },
        )

    if auth_code.client_id != client.client_id:
        raise BadRequestError(
            error_code="invalid_client_for_authorization_code",
            detail="Invalid client for authorization code",
            message={
                "en": "Invalid client for authorization code",
                "fa": "ابزار ورود جانبی با این کد تأیید مطابقت ندارد.",
            },
        )

    if auth_code.redirect_uri != redirect_uri:
        raise BadRequestError(
            error_code="invalid_redirect_uri",
            detail="Invalid redirect_uri",
            message={
                "en": "Invalid redirect_uri",
                "fa": "آدرس بازگشت نامعتبر است.",
            },
        )

    if auth_code.is_used:
        raise BadRequestError(
            error_code="authorization_code_already_used",
            detail="Authorization code already used",
            message={
                "en": "Authorization code already used",
                "fa": "این کد تأیید ورود قبلاً استفاده شده.",
            },
        )

    _validate_pkce(auth_code, code_verifier)

    consume_result = await AuthorizationCode.get_pymongo_collection().update_one(
        {
            "uid": auth_code.uid,
            "tenant_id": tenant.uid,
            "is_used": False,
        },
        {"$set": {"is_used": True}},
    )
    if consume_result.modified_count != 1:
        raise BadRequestError(
            error_code="authorization_code_already_used",
            detail="Authorization code already used",
        )
    auth_code.is_used = True

    user = await User.get_item(uid=auth_code.user_id, tenant_id=tenant.uid)
    if not user:
        raise BadRequestError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )

    return user, auth_code.scope, auth_code.nonce


def create_service_account_access_token(
    *,
    tenant: Tenant,
    client_id: str,
    scopes: list[str],
    workspace_id: str | None,
    user_id: str | None,
    created_by: str | None,
    sub_type: str,
    aud: str | None = None,
) -> TokenResponseSchema:
    """Issue a JWT access token for an API key / agent via client_credentials."""
    now = int(time.time())
    expires_in = tenant.config.token.access_timeout
    payload = {
        "jti": str(uuid.uuid4()),
        "token_type": "access",
        "iss": tenant.primary_url,
        "aud": aud or client_id,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "sub": client_id,
        "tenant_id": tenant.uid,
        "workspace_id": workspace_id,
        "scopes": scopes,
        "amr": ["client_credentials"],
        "sub_type": sub_type,
        "user_id": user_id,
        "created_by": created_by,
    }
    access_token = tenant.sign_jwt(payload)
    return TokenResponseSchema(
        access_token=access_token,
        token_type="Bearer",  # ruff:ignore[hardcoded-password-func-arg]
        expires_in=expires_in,
        refresh_token=None,
        scope=" ".join(scopes),
        id_token=None,
    )


def _grant_requested_scopes(*, requested: list[str], allowed: list[str]) -> list[str]:
    """Return granted scopes; requested must be a subset of allowed."""
    from usso import authorization

    if not requested:
        return allowed
    for scope in requested:
        if not authorization.has_subset_scope(subset_scope=scope, user_scopes=allowed):
            raise BadRequestError(
                error_code="invalid_scope",
                detail=f"Scope not allowed: {scope}",
                message={
                    "en": "Requested scope is not allowed.",
                    "fa": "سطح دسترسی درخواستی مجاز نیست.",
                },
            )
    return requested


def _invalid_client() -> UnauthorizedError:
    return UnauthorizedError(
        error_code="invalid_client",
        detail="Invalid client credentials",
        message={
            "en": "Invalid client credentials.",
            "fa": "اطلاعات کلاینت نامعتبر است.",
        },
    )


async def exchange_service_account_client_credentials(
    *,
    tenant: Tenant,
    client_id: str,
    client_secret: str | None,
    scope: str | None,
) -> TokenResponseSchema:
    """
    Authenticate API key or agent with client_id + client_secret.

    Falls through with UnauthorizedError when neither matches.
    """
    from apps.identity.agent.models import Agent
    from apps.identity.agent.services import verify_agent_client_secret
    from apps.identity.api_key.models import APIKey
    from apps.identity.api_key.services import (
        _validate_api_key_state,
        enforce_api_key_ip_whitelist,
        enforce_api_key_rate_limit,
        record_api_key_usage,
        verify_client_secret,
    )
    from utils.request_context import client_ip_var, user_agent_var

    if not client_id or not client_secret:
        raise UnauthorizedError(
            error_code="invalid_client",
            detail="client_id and client_secret are required",
            message={
                "en": "client_id and client_secret are required.",
                "fa": "شناسه و رمز کلاینت لازم است.",
            },
        )

    requested = [s for s in (scope or "").split() if s]

    api_key = await APIKey.find_one({
        "uid": client_id,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if api_key is not None:
        if not verify_client_secret(db_key=api_key, client_secret=client_secret):
            raise _invalid_client()
        _validate_api_key_state(api_key)
        client_ip = client_ip_var.get()
        user_agent = user_agent_var.get()
        enforce_api_key_ip_whitelist(api_key, client_ip=client_ip)
        await enforce_api_key_rate_limit(api_key)
        await record_api_key_usage(api_key, client_ip=client_ip, user_agent=user_agent)
        granted = _grant_requested_scopes(
            requested=requested, allowed=list(api_key.scopes or [])
        )
        return create_service_account_access_token(
            tenant=tenant,
            client_id=api_key.uid,
            scopes=granted,
            workspace_id=api_key.workspace_id,
            user_id=api_key.user_id,
            created_by=api_key.created_by,
            sub_type="api_key",
        )

    agent = await Agent.find_one({
        "uid": client_id,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if agent is not None:
        if not agent.is_active:
            raise UnauthorizedError(
                error_code="agent_not_active",
                detail="Agent is not active",
                message={
                    "en": "Agent is not active.",
                    "fa": "این عامل غیرفعال است.",
                },
            )
        if not verify_agent_client_secret(agent=agent, client_secret=client_secret):
            raise _invalid_client()
        granted = _grant_requested_scopes(
            requested=requested, allowed=list(agent.scopes or [])
        )
        return create_service_account_access_token(
            tenant=tenant,
            client_id=agent.uid,
            scopes=granted,
            workspace_id=agent.workspace_id,
            user_id=agent.user_id,
            created_by=agent.created_by,
            sub_type="agent",
        )

    raise UnauthorizedError(
        error_code="invalid_client",
        detail="Invalid client_id",
        message={
            "en": "Invalid client_id.",
            "fa": "شناسه کلاینت نامعتبر است.",
        },
    )


async def create_tokens(
    client: OAuthClient,
    user: User,
    tenant: Tenant,
    scope: list[str],
    nonce: str | None = None,
) -> TokenResponseSchema:
    """Create access and refresh tokens."""
    # Revoke existing tokens for this client/user combination
    existing_tokens = await OAuthToken.find({
        "client_id": client.client_id,
        "user_id": user.uid,
        "tenant_id": tenant.uid,
        "is_revoked": False,
    }).to_list()

    for token in existing_tokens:
        await token.revoke_related_tokens()

    # Create access token
    access_expires_in = tenant.config.token.access_timeout
    refresh_expires_in = tenant.config.token.refresh_timeout
    access_token = OAuthToken.create_access_token(
        client_id=client.client_id,
        user_id=user.uid,
        tenant_id=tenant.uid,
        scope=scope,
        expires_in=access_expires_in,
    )
    await access_token.save()

    # Create refresh token
    refresh_token = OAuthToken.create_refresh_token(
        client_id=client.client_id,
        user_id=user.uid,
        tenant_id=tenant.uid,
        scope=scope,
        access_token_id=access_token.uid,
        expires_in=refresh_expires_in,
    )
    await refresh_token.save()

    # Update access token with refresh token reference
    access_token.refresh_token = refresh_token.refresh_token
    await access_token.save()

    # Create ID token if openid scope is present
    id_token = None
    if Scope.OPENID.value in scope:
        id_token = await create_id_token(
            user=user, tenant=tenant, client=client, scope=scope, nonce=nonce
        )

    return TokenResponseSchema(
        access_token=access_token.raw_token,
        token_type="Bearer",  # ruff:ignore[hardcoded-password-func-arg]
        expires_in=access_expires_in,
        refresh_token=refresh_token.raw_token,
        scope=" ".join(scope),
        id_token=id_token,
    )


async def create_id_token(
    user: User,
    tenant: Tenant,
    client: OAuthClient,
    scope: list[str],
    nonce: str | None = None,
) -> str:
    """Create ID token."""
    now = int(time.time())

    # Build claims based on scopes
    claims = {
        "iss": tenant.primary_url,
        "sub": user.uid,
        "aud": client.client_id,
        "exp": now + tenant.config.token.access_timeout,
        "iat": now,
        "auth_time": now,
    }

    if nonce:
        claims["nonce"] = nonce

    if Scope.PROFILE.value in scope:
        claims.update({
            "name": user.name,
            "given_name": user.name.split()[0] if user.name else None,
            "family_name": " ".join(user.name.split()[1:])
            if user.name and len(user.name.split()) > 1
            else None,
            "preferred_username": await user.get_username(),
        })

    if Scope.EMAIL.value in scope:
        # Get user email from identifiers
        identifiers = await user.get_identifiers()
        email_identifier = next((i for i in identifiers if i.type == "email"), None)
        if email_identifier:
            claims["email"] = email_identifier.identifier
            claims["email_verified"] = (
                getattr(email_identifier, "verified_at", None) is not None
            )

    # Sign the token
    return tenant.sign_jwt(claims)


async def refresh_access_token(
    refresh_token: str, client: OAuthClient, tenant: Tenant
) -> TokenResponseSchema:
    """Refresh access token using refresh token."""
    # Get refresh token
    token = await OAuthToken.get_by_refresh_token(refresh_token, tenant.uid)

    if not token:
        raise BadRequestError(
            error_code="invalid_refresh_token",
            detail="Invalid refresh token",
            message={
                "en": "Invalid refresh token",
                "fa": "لطفاً دوباره وارد شوید.",
            },
        )

    if token.client_id != client.client_id:
        raise BadRequestError(
            error_code="invalid_client_for_refresh_token",
            detail="Invalid client for refresh token",
            message={
                "en": "Invalid client for refresh token",
                "fa": "ابزار ورود جانبی با این درخواست مطابقت ندارد.",
            },
        )

    # Get user
    user = await User.get_item(uid=token.user_id, tenant_id=tenant.uid)
    if not user:
        raise BadRequestError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )

    consume_result = await OAuthToken.get_pymongo_collection().update_one(
        {
            "uid": token.uid,
            "tenant_id": tenant.uid,
            "client_id": client.client_id,
            "is_revoked": False,
        },
        {"$set": {"is_revoked": True}},
    )
    if consume_result.modified_count != 1:
        raise BadRequestError(
            error_code="invalid_refresh_token",
            detail="Invalid refresh token",
            message={
                "en": "Invalid refresh token",
                "fa": "لطفاً دوباره وارد شوید.",
            },
        )
    token.is_revoked = True

    # Revoke old tokens
    await token.revoke_related_tokens()

    # Create new tokens
    return await create_tokens(
        client=client, user=user, tenant=tenant, scope=token.scope
    )


async def introspect_token(
    token: str, tenant: Tenant
) -> TokenIntrospectionResponseSchema:
    """Introspect token and return token information."""
    oauth_token = await OAuthToken.get_by_token(token, tenant.uid)

    if not oauth_token:
        return TokenIntrospectionResponseSchema(active=False)

    # Get user
    user = await User.get_item(uid=oauth_token.user_id, tenant_id=tenant.uid)
    if not user:
        return TokenIntrospectionResponseSchema(active=False)

    return TokenIntrospectionResponseSchema(
        active=True,
        scope=" ".join(oauth_token.scope),
        client_id=oauth_token.client_id,
        username=await user.get_username(),
        token_type=oauth_token.token_type.value,
        exp=int(oauth_token.expires_at.timestamp()),
        iat=int((oauth_token.expires_at - timedelta(seconds=3600)).timestamp()),
        sub=user.uid,
        aud=oauth_token.client_id,
        iss=tenant.primary_url,
        jti=oauth_token.uid,
    )


async def get_user_info(access_token: str, tenant: Tenant) -> UserInfoResponseSchema:
    """Get user information from access token."""
    oauth_token = await OAuthToken.get_by_token(access_token, tenant.uid)

    if not oauth_token:
        raise UnauthorizedError(
            error_code="invalid_access_token",
            detail="Invalid access token",
            message={
                "en": "Invalid access token",
                "fa": "لطفاً دوباره وارد شوید.",
            },
        )

    # Get user
    user = await User.get_item(uid=oauth_token.user_id, tenant_id=tenant.uid)
    if not user:
        raise UnauthorizedError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )

    # Get identifiers
    identifiers = await user.get_identifiers()
    # Get email identifier
    email_identifier = next((i for i in identifiers if i.type == "email"), None)
    email = email_identifier.identifier if email_identifier else None
    # Get phone identifier
    phone_identifier = next((i for i in identifiers if i.type == "phone"), None)
    phone = phone_identifier.identifier if phone_identifier else None

    return UserInfoResponseSchema(
        sub=user.uid,
        name=user.name,
        given_name=user.name.split()[0] if user.name else None,
        family_name=" ".join(user.name.split()[1:])
        if user.name and len(user.name.split()) > 1
        else None,
        preferred_username=await user.get_username(),
        email=email,
        email_verified=(getattr(email_identifier, "verified_at", None) is not None)
        if email_identifier
        else None,
        phone_number=phone,
        phone_number_verified=(
            getattr(phone_identifier, "verified_at", None) is not None
        )
        if phone_identifier
        else None,
        updated_at=int(time.time()),
    )


async def register_client(
    request: ClientRegistrationRequestSchema, tenant: Tenant, user: User
) -> ClientRegistrationResponseSchema:
    """Register a new OAuth client."""
    # Generate client credentials
    client_id = OAuthClient.generate_client_id()
    client_secret = OAuthClient.generate_client_secret()

    # Create client
    client = OAuthClient(
        client_id=client_id,
        client_secret=PasswordHasherService().hash_password(client_secret),
        client_name=request.client_name,
        client_type="confidential",  # Default to confidential
        redirect_uris=request.redirect_uris,
        grant_types=request.grant_types,
        response_types=request.response_types,
        logo_uri=request.logo_uri,
        client_uri=request.client_uri,
        policy_uri=request.policy_uri,
        tos_uri=request.tos_uri,
        tenant_id=tenant.uid,
        user_id=user.uid,
    )

    await client.save()

    # Generate registration access token
    registration_access_token = secrets.token_urlsafe(32)

    # Save registration access token to client
    client.registration_access_token = PasswordHasherService().hash_password(
        registration_access_token
    )
    await client.save()

    return ClientRegistrationResponseSchema(
        **client.model_dump(exclude={"client_secret", "registration_access_token"}),
        client_secret=client_secret,
        registration_access_token=registration_access_token,
        client_id_issued_at=int(time.time()),
        client_secret_expires_at=0,
    )


async def revoke_token(token: str, client: OAuthClient, tenant: Tenant) -> None:
    """Revoke a token."""
    oauth_token = await OAuthToken.get_by_token(token, tenant.uid)

    if oauth_token and oauth_token.client_id == client.client_id:
        await oauth_token.revoke_related_tokens()
