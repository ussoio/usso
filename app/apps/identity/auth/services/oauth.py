"""
OAuth / OIDC client helpers for social login.

Supports authorization-code flow with optional PKCE and
client_secret_basic token authentication (required by Telegram OIDC).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import secrets
import urllib.parse
from typing import Any

import httpx
from aiocache import cached
from fastapi import Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from starlette.datastructures import URL
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT

from server.config import Settings
from server.exceptions import BadRequestError
from utils.outbound import UnsafeOutboundURLError, validate_public_url

from ....tenant.models import Tenant
from ....tenant.secrets import OAuthSecret
from ...profile.models import Profile
from ...user.models import User
from ...user.services import (
    add_credential,
    find_or_create_user,
)
from ..enums import AuthIdentifier, AuthSecret
from ..schemas import (
    LoginRequest,
)
from .basics import get_tenant_url
from .telegram import (
    TELEGRAM_OIDC_DISCOVERY_URL,
    ensure_telegram_discovery,
    is_telegram_oidc,
    oidc_audience_matches,
    telegram_display_name,
    telegram_user_id_from_claims,
)

logger = logging.getLogger(__name__)


class OAuthSession(BaseModel):
    """Authorization redirect session data."""

    authorization_url: str
    state: str
    code_verifier: str | None = None
    nonce: str | None = None


@cached(ttl=3600)  # 1 hour
async def fetch_oidc_config(discovery_url: str) -> dict:
    """Fetch OIDC configuration from discovery URL."""
    await validate_public_url(discovery_url)
    async with httpx.AsyncClient(proxy=os.getenv("PROXY")) as client:
        resp = await client.get(discovery_url, timeout=10)
        resp.raise_for_status()
        return resp.json()


async def _validated_oidc_endpoint(config: dict, field: str) -> str:
    """Return a required public HTTPS endpoint from OIDC discovery metadata."""
    endpoint = config.get(field)
    if not isinstance(endpoint, str) or not endpoint:
        raise BadRequestError(
            error_code="invalid_oidc_configuration",
            detail=f"OIDC provider did not publish a valid {field}",
        )
    try:
        await validate_public_url(endpoint)
    except UnsafeOutboundURLError as exc:
        raise BadRequestError(
            error_code="unsafe_oidc_endpoint",
            detail=f"OIDC {field} must resolve to a public HTTPS endpoint",
        ) from exc
    return endpoint


def build_url_with_params(base_url: str, params: dict) -> str:
    """Safely append query params to a base URL (handles existing params)."""
    url_parts = list(urllib.parse.urlparse(base_url))
    query = dict(urllib.parse.parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(url_parts)


def generate_oauth_redirect_uri(
    tenant: Tenant, provider: str, url: URL | str | None = None
) -> str:
    """Build the redirect URI for OAuth/OIDC callback."""
    url = get_tenant_url(tenant, url)
    return f"{url}{Settings.base_path}/auth/oauth/{provider}/callback"


def _allowed_return_domains(tenant: Tenant) -> set[str]:
    """Normalize explicitly configured tenant return domains."""
    configured_domains = (
        set(tenant.domains or [])
        | {tenant.primary_domain}
        | set(tenant.config.allowed_return_domains)
    )
    return {
        (urllib.parse.urlsplit(domain).netloc if "://" in domain else domain)
        .strip()
        .lower()
        .rstrip("/")
        for domain in configured_domains
        if domain
    }


def _absolute_return_url_is_allowed(
    parsed: urllib.parse.SplitResult, allowed_domains: set[str]
) -> bool:
    """Validate an absolute return URL against scheme and host policy."""
    if parsed.scheme not in {"http", "https"}:
        return False
    has_credentials = parsed.username is not None or parsed.password is not None
    if has_credentials or parsed.netloc.lower() not in allowed_domains:
        return False
    return not (
        parsed.scheme == "http"
        and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
    )


def sanitize_return_url(return_url: str | None, tenant: Tenant) -> str | None:
    """Ensure the return URL is safe and scoped to the tenant."""
    if not return_url:
        return None

    try:
        if any(ord(char) < 32 for char in return_url) or "\\" in return_url:
            return None
        parsed = urllib.parse.urlsplit(return_url)

        if parsed.netloc:
            if not _absolute_return_url_is_allowed(
                parsed, _allowed_return_domains(tenant)
            ):
                return None
            return return_url

        # Treat as relative path
        if parsed.scheme or return_url.startswith("//"):
            return None
        if not return_url.startswith("/"):
            return f"/{return_url}"
    except Exception:  # pragma: no cover - defensive fallback
        return None

    return return_url


OAUTH_COOKIES = (
    "usso_oidc_state",
    "usso_oidc_verifier",
    "usso_oidc_nonce",
    "usso_oauth_return_url",
    "usso_oauth_handoff",
    "usso_oauth_step_up",
)
_OAUTH_BROWSER_PATH = re.compile(r"/auth/oauth/[^/]+/(authorize|callback)/?$")


async def oauth_error_redirect(
    request: Request, error_code: str, retry_after: object = None
) -> RedirectResponse | None:
    """
    Send a browser OAuth failure back to the app instead of raw JSON.

    authorize/callback are full-page navigations, so a JSON error leaves the
    user on a blank page. Redirect to the sanitized return URL with
    ``auth_error`` (and ``retry_after``) so the sign-in page can explain it.
    """
    match = _OAUTH_BROWSER_PATH.search(request.url.path)
    if request.method != "GET" or not match:
        return None

    from ....tenant.services import get_request_tenant

    try:
        tenant = await get_request_tenant(request)
    except Exception:
        return None

    raw_return_url = (
        request.query_params.get("return_url")
        if match.group(1) == "authorize"
        else request.cookies.get("usso_oauth_return_url")
    )
    return_url = sanitize_return_url(raw_return_url, tenant) or sanitize_return_url(
        tenant.config.default_redirect_url, tenant
    )
    if not return_url:
        return None

    params = {"auth_error": error_code}
    if retry_after:
        params["retry_after"] = str(retry_after)
    response = RedirectResponse(
        build_url_with_params(return_url, params), status_code=303
    )
    for cookie in OAUTH_COOKIES:
        response.delete_cookie(cookie)
    return response


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for S256 PKCE."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _auth_options(provider: str, secrets_data: OAuthSecret) -> tuple[bool, str]:
    """Resolve PKCE + token auth method (Telegram forces PKCE + basic)."""
    if is_telegram_oidc(provider, secrets_data):
        return True, "client_secret_basic"
    return secrets_data.use_pkce, secrets_data.token_auth_method


def resolve_provider_secret(tenant: Tenant, provider: str) -> OAuthSecret:
    """Load provider secret, applying Telegram discovery default when needed."""
    secrets_data = tenant.secrets.oauth_secrets.get(provider)
    if not secrets_data:
        raise BadRequestError(
            error_code="provider_not_configured",
            detail="OAuth provider not configured",
            message={
                "en": "OAuth provider not configured",
                "fa": "سرویس ورود تنظیم نشده است.",
            },
        )
    if is_telegram_oidc(provider, secrets_data):
        if not secrets_data.discovery_url:
            secrets_data = secrets_data.model_copy(
                update={"discovery_url": TELEGRAM_OIDC_DISCOVERY_URL}
            )
        else:
            secrets_data = ensure_telegram_discovery(secrets_data)
        if not secrets_data.scopes or secrets_data.scopes == [
            "openid",
            "profile",
            "email",
        ]:
            # Default OAuthSecret scopes include email; Telegram has no email scope.
            secrets_data = secrets_data.model_copy(
                update={"scopes": ["openid", "profile"]}
            )
        else:
            # ``id`` (Bot API user id) only comes with profile. Keep any extra
            # scopes the tenant configured, but never drop profile.
            scopes = list(secrets_data.scopes)
            if "openid" not in scopes:
                scopes.insert(0, "openid")
            if "profile" not in scopes:
                scopes.append("profile")
            if scopes != list(secrets_data.scopes):
                secrets_data = secrets_data.model_copy(update={"scopes": scopes})
    return secrets_data


OAUTH_STEP_UP_MAX_AGE_SECONDS = 300


def supports_oauth_step_up(provider: str, secrets_data: OAuthSecret | None) -> bool:
    """
    Return True when re-login with this provider may issue a secure token.

    Policy: only OTP and passkey open a secure session. OAuth re-login is
    disabled for every provider: Google often skips the fresh login (no
    ``auth_time``), and Telegram cannot force one at all.
    """
    del provider, secrets_data
    return False


def is_fresh_oauth_authentication(
    userinfo: dict[str, Any],
    *,
    now: int,
    max_age: int = OAUTH_STEP_UP_MAX_AGE_SECONDS,
) -> bool:
    """Return True when the id_token proves auth within ``max_age`` seconds."""
    auth_time = userinfo.get("auth_time")
    if isinstance(auth_time, bool) or not isinstance(auth_time, int | float):
        return False
    return 0 <= now - int(auth_time) <= max_age


async def create_oauth_session(
    *,
    tenant: Tenant,
    provider: str,
    url: URL | str | None = None,
    step_up: bool = False,
) -> OAuthSession:
    """
    Create an OAuth session and return authorize URL + state (+ PKCE).

    ``step_up`` forces a fresh provider login (``prompt=login``, ``max_age=0``)
    so the callback can issue a secure token from proven, recent auth.
    """
    secrets_data = resolve_provider_secret(tenant, provider)
    oidc_config = await fetch_oidc_config(secrets_data.discovery_url)
    client_id = secrets_data.client_id
    redirect_uri = generate_oauth_redirect_uri(tenant, provider, url)
    scopes = secrets_data.scopes or []
    use_pkce, _ = _auth_options(provider, secrets_data)
    authorization_endpoint = await _validated_oidc_endpoint(
        oidc_config, "authorization_endpoint"
    )

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
    }
    if step_up:
        params["prompt"] = "login"
        params["max_age"] = "0"
    code_verifier: str | None = None
    if use_pkce:
        code_verifier, code_challenge = _pkce_pair()
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    authorization_url = build_url_with_params(authorization_endpoint, params)
    return OAuthSession(
        authorization_url=authorization_url,
        state=state,
        code_verifier=code_verifier,
        nonce=nonce,
    )


async def exchange_oauth_code_for_userinfo(
    *,
    code: str,
    tenant: Tenant,
    provider: str,
    expected_nonce: str,
    url: URL | str | None = None,
    code_verifier: str | None = None,
) -> tuple[str, dict, str]:
    """Exchange the authorization code for tokens and extract user info."""
    secrets_data = resolve_provider_secret(tenant, provider)
    oidc_config = await fetch_oidc_config(secrets_data.discovery_url)
    client_id = secrets_data.client_id
    client_secret = secrets_data.client_secret
    redirect_uri = generate_oauth_redirect_uri(tenant, provider, url=url)
    token_endpoint = await _validated_oidc_endpoint(oidc_config, "token_endpoint")
    _, token_auth_method = _auth_options(provider, secrets_data)

    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    headers: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
    if token_auth_method == "client_secret_basic":
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers["Authorization"] = f"Basic {basic}"
    else:
        data["client_secret"] = client_secret

    if code_verifier:
        data["code_verifier"] = code_verifier

    async with httpx.AsyncClient(proxy=os.getenv("PROXY")) as client:
        try:
            resp = await client.post(
                token_endpoint, data=data, headers=headers, timeout=10
            )
            resp.raise_for_status()
            token_response = resp.json()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response is not None else None
            # Log only the OAuth error fields (RFC 6749 §5.2), never tokens.
            try:
                body = exc.response.json() if exc.response is not None else {}
            except ValueError:
                body = {}
            logger.warning(
                "OIDC token exchange failed: provider=%s status=%s error=%s "
                "description=%s redirect_uri=%s",
                provider,
                status,
                body.get("error") if isinstance(body, dict) else None,
                body.get("error_description") if isinstance(body, dict) else None,
                redirect_uri,
            )
            raise BadRequestError(
                error_code="oauth_token_exchange_failed",
                detail=f"OIDC token endpoint returned HTTP {status}",
                message={
                    "en": "Login with this provider failed. Please try again.",
                    "fa": "ورود با این سرویس ناموفق بود. دوباره تلاش کنید.",
                },
            ) from exc
        except httpx.HTTPError as exc:
            raise BadRequestError(
                error_code="oauth_token_exchange_failed",
                detail=f"OIDC token endpoint error: {type(exc).__name__}",
                message={
                    "en": "Login with this provider failed. Please try again.",
                    "fa": "ورود با این سرویس ناموفق بود. دوباره تلاش کنید.",
                },
            ) from exc

    issuer = oidc_config.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        raise BadRequestError(
            error_code="invalid_oidc_configuration",
            detail="OIDC provider did not publish an issuer",
        )
    jwks_uri = await _validated_oidc_endpoint(oidc_config, "jwks_uri")
    # Skip library audience check: Telegram (and some IdPs) may emit ``aud`` as
    # an integer bot id while our client_id is a string.
    jwt = JWT(
        token=token_response["id_token"],
        config=JWTConfig(
            jwks_url=jwks_uri,
            issuer=issuer,
            audience=None,
        ),
    )
    try:
        jwt.verify()
    except Exception as exc:
        raise BadRequestError(
            error_code="invalid_id_token",
            detail=f"OIDC id_token verification failed: {exc}",
            message={
                "en": "Invalid login response",
                "fa": "پاسخ ورود نامعتبر است.",
            },
        ) from exc
    userinfo = dict(jwt.unverified_payload)
    if not oidc_audience_matches(userinfo.get("aud"), client_id):
        raise BadRequestError(
            error_code="invalid_audience",
            detail="OIDC id_token audience mismatch",
            message={
                "en": "Invalid login response",
                "fa": "پاسخ ورود نامعتبر است.",
            },
        )
    token_nonce = userinfo.get("nonce")
    if not isinstance(token_nonce, str) or not secrets.compare_digest(
        token_nonce, expected_nonce
    ):
        raise BadRequestError(
            error_code="invalid_nonce",
            detail="OIDC nonce mismatch",
            message={"en": "Invalid login response", "fa": "پاسخ ورود نامعتبر است."},
        )

    return token_response["id_token"], userinfo, jwks_uri


class OAuthIdentity(BaseModel):
    """Resolved login identity from OIDC userinfo."""

    identifier_type: AuthIdentifier
    identifier: str
    method: AuthSecret
    name: str | None = None
    profile_data: dict[str, Any] = Field(default_factory=dict)


def _bounded_claim(userinfo: dict[str, Any], name: str, limit: int = 256) -> str | None:
    value = userinfo.get(name)
    return value[:limit] if isinstance(value, str) and value else None


def _safe_oauth_profile_data(
    *, provider: str, userinfo: dict[str, Any]
) -> dict[str, Any]:
    """Map OIDC claims to non-privileged profile fields only."""
    profile_data: dict[str, Any] = {}
    first_name = _bounded_claim(userinfo, "given_name")
    last_name = _bounded_claim(userinfo, "family_name")
    if first_name:
        profile_data["first_name"] = first_name
    if last_name:
        profile_data["last_name"] = last_name

    picture = _bounded_claim(userinfo, "picture", 2048)
    if picture:
        parsed_picture = urllib.parse.urlsplit(picture)
        if (
            parsed_picture.scheme == "https"
            and parsed_picture.hostname
            and not parsed_picture.username
            and not parsed_picture.password
        ):
            profile_data["avatar_url"] = picture

    safe_claims = {
        key: value
        for key in ("sub", "name", "locale")
        if (value := _bounded_claim(userinfo, key)) is not None
    }
    profile_data["meta_data"] = {"oauth": {"provider": provider, **safe_claims}}
    return profile_data


def _is_blank_profile_value(value: object) -> bool:
    if value is None:
        return True
    return bool(isinstance(value, str) and not value.strip())


def merge_oauth_into_profile(
    *, existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    """
    Merge OAuth profile hints without overriding user-set fields.

    Existing non-blank ``first_name`` / ``last_name`` / ``avatar_url`` win.
    ``meta_data`` keeps user keys (e.g. personal_prompts) and updates
    ``meta_data.oauth`` only.
    """
    merged = dict(existing)
    for key, value in incoming.items():
        if key == "meta_data":
            continue
        if _is_blank_profile_value(merged.get(key)) and not _is_blank_profile_value(
            value
        ):
            merged[key] = value

    previous_meta = dict(merged.get("meta_data") or {})
    incoming_meta = dict(incoming.get("meta_data") or {})
    previous_oauth = dict(previous_meta.get("oauth") or {})
    incoming_oauth = dict(incoming_meta.get("oauth") or {})
    if incoming_oauth:
        previous_meta["oauth"] = {**previous_oauth, **incoming_oauth}
    if previous_meta:
        merged["meta_data"] = previous_meta
    return merged


def resolve_oauth_identity(
    *, provider: str, userinfo: dict[str, Any], secrets_data: OAuthSecret | None = None
) -> OAuthIdentity:
    """Map OIDC claims to USSO identifier + auth method."""
    if is_telegram_oidc(provider, secrets_data):
        return OAuthIdentity(
            identifier_type=AuthIdentifier.TELEGRAM_ID,
            identifier=telegram_user_id_from_claims(userinfo),
            method=AuthSecret.TELEGRAM_TOKEN,
            name=telegram_display_name(userinfo),
            profile_data=userinfo,
        )

    email = userinfo.get("email")
    if not email:
        raise BadRequestError(
            error_code="oauth_email_missing",
            detail="OAuth userinfo missing email",
            message={
                "en": "OAuth account has no email.",
                "fa": "حساب ورود جانبی ایمیل ندارد.",
            },
        )
    if userinfo.get("email_verified") is not True:
        raise BadRequestError(
            error_code="oauth_email_unverified",
            detail="OAuth provider did not verify the email address",
            message={
                "en": "The sign-in provider has not verified this email address.",
                "fa": "سرویس ورود، این نشانی ایمیل را تأیید نکرده است.",
            },
        )
    return OAuthIdentity(
        identifier_type=AuthIdentifier.EMAIL,
        identifier=email,
        method=AuthSecret.OAUTH,
        name=userinfo.get("name"),
        profile_data=userinfo,
    )


async def create_oauth_credential(
    *,
    tenant: Tenant,
    provider: str,
    email: str | None = None,
    identifier: str | None = None,
    identifier_type: AuthIdentifier = AuthIdentifier.EMAIL,
    method: AuthSecret = AuthSecret.OAUTH,
    jwks_uri: str,
    userinfo: dict | None = None,
) -> User:
    """Create OAuth credential for user."""
    resolved_identifier = identifier or email
    if not resolved_identifier:
        raise BadRequestError(
            error_code="oauth_identifier_missing",
            detail="OAuth identifier missing",
            message={
                "en": "OAuth account identifier is missing.",
                "fa": "شناسه حساب ورود جانبی موجود نیست.",
            },
        )

    register_request = LoginRequest.model_validate({
        "type": identifier_type,
        "identifier": resolved_identifier,
        "method": method,
        "secret": jwks_uri,
    })

    user, is_created = await find_or_create_user(
        login_request=register_request, tenant=tenant
    )
    if not is_created:
        await add_credential(user=user, secret=register_request)

    # Persist fetched profile data
    profile = await Profile.get_by_user_id(tenant_id=tenant.uid, user_id=user.uid)
    if not profile:
        profile = Profile(tenant_id=tenant.uid, user_id=user.uid, profile_data={})
    if userinfo:
        prev_profile_data = {}
        if profile.profile_data:
            if hasattr(profile.profile_data, "model_dump"):
                prev_profile_data = profile.profile_data.model_dump()
            else:
                prev_profile_data = dict(profile.profile_data)

        safe_profile_data = _safe_oauth_profile_data(
            provider=provider, userinfo=userinfo
        )
        profile.profile_data = merge_oauth_into_profile(
            existing=prev_profile_data,
            incoming=safe_profile_data,
        )
    await profile.save()

    return user
