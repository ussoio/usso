"""Telegram Login via OpenID Connect (oauth.telegram.org)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT

from apps.tenant.models import Tenant
from apps.tenant.secrets import OAuthSecret
from server.exceptions import BadRequestError, UnauthorizedError

from ..enums import AuthIdentifier, AuthSecret
from ..schemas import LoginRequest

TELEGRAM_PROVIDER = "telegram"
TELEGRAM_OIDC_DISCOVERY_URL = (
    "https://oauth.telegram.org/.well-known/openid-configuration"
)
TELEGRAM_OIDC_ISSUER = "https://oauth.telegram.org"


class TelegramIdTokenSchema(BaseModel):
    """Payload from Telegram Login JS SDK / OIDC (id_token)."""

    id_token: str = Field(..., description="OIDC ID token from Telegram Login")


def is_telegram_oidc(provider: str, secrets_data: OAuthSecret | None = None) -> bool:
    """Return True when the provider is Telegram's OIDC IdP."""
    if provider == TELEGRAM_PROVIDER:
        return True
    return bool(
        secrets_data and "oauth.telegram.org" in (secrets_data.discovery_url or "")
    )


def require_telegram_oauth(tenant: Tenant) -> OAuthSecret:
    """Return configured Telegram OIDC client or raise."""
    secret = tenant.secrets.oauth_secrets.get(TELEGRAM_PROVIDER)
    if secret is None or not secret.client_id or not secret.client_secret:
        raise BadRequestError(
            error_code="telegram_not_configured",
            detail="Telegram OIDC login is not configured for this tenant",
            message={
                "en": "Telegram login is not configured.",
                "fa": "ورود با تلگرام در این سامانه فعال نیست.",
            },
        )
    return secret


def ensure_telegram_discovery(secrets_data: OAuthSecret) -> OAuthSecret:
    """Fill Telegram discovery URL when omitted."""
    if secrets_data.discovery_url:
        return secrets_data
    return secrets_data.model_copy(
        update={"discovery_url": TELEGRAM_OIDC_DISCOVERY_URL}
    )


def telegram_user_id_from_claims(claims: dict[str, Any]) -> str:
    """
    Extract Telegram numeric user id from ID token claims.

    Prefer the profile-scope ``id`` claim (Bot API user id). A numeric ``sub``
    that already looks like a Telegram user id is accepted as fallback; the
    opaque OIDC ``sub`` Telegram usually issues is not.
    """
    from usso.utils import validators

    candidates: list[object] = [claims.get("id"), claims.get("telegram_id")]
    sub = claims.get("sub")
    if sub is not None:
        candidates.append(sub)

    for raw in candidates:
        if raw is None or isinstance(raw, bool):
            continue
        text = str(raw).strip()
        if not text:
            continue
        is_valid, _error, canonical = validators.validate_telegram_id(text)
        if is_valid and canonical:
            return str(canonical)

    claim_keys = sorted(str(key) for key in claims)
    openid_only = set(claim_keys) <= {
        "aud",
        "exp",
        "iat",
        "iss",
        "nonce",
        "sub",
        "auth_time",
        "jti",
    }
    if openid_only:
        detail = (
            "Telegram id_token has only openid claims (no profile id). "
            "In @BotFather → Login Widget → Advanced, set the signing "
            "algorithm to RS256 or ES256 (EdDSA/ES256K reject profile). "
            f"keys={claim_keys}"
        )
        message = {
            "en": (
                "Telegram returned no profile. In BotFather Login Widget → "
                "Advanced, set signing algorithm to RS256 (not EdDSA/ES256K)."
            ),
            "fa": (
                "تلگرام پروفایل برنگرداند. در BotFather بخش Login Widget → "
                "Advanced الگوریتم امضا را روی RS256 بگذارید "
                "(نه EdDSA یا ES256K)."
            ),
        }
    else:
        detail = f"Telegram id_token missing numeric user id claim (keys={claim_keys})"
        message = {
            "en": "Telegram login data is invalid.",
            "fa": "داده ورود تلگرام نامعتبر است.",
        }
    raise UnauthorizedError(
        error_code="telegram_auth_invalid",
        detail=detail,
        message=message,
    )


def telegram_display_name(claims: dict[str, Any]) -> str | None:
    """Best-effort display name from OIDC claims."""
    if name := claims.get("name"):
        return str(name)
    given = claims.get("given_name")
    family = claims.get("family_name")
    parts = [str(p) for p in (given, family) if p]
    if parts:
        return " ".join(parts)
    username = claims.get("preferred_username")
    return str(username) if username else None


def oidc_audience_matches(aud: object, client_id: str) -> bool:
    """Return True when JWT aud matches client_id (string or numeric)."""
    expected = str(client_id).strip()
    if not expected:
        return False
    if isinstance(aud, list):
        return any(str(item).strip() == expected for item in aud)
    if aud is None or isinstance(aud, bool):
        return False
    return str(aud).strip() == expected


def verify_telegram_id_token(
    *,
    id_token: str,
    client_id: str,
    jwks_uri: str,
) -> dict[str, Any]:
    """
    Verify Telegram OIDC id_token (signature + iss + aud).

    ``aud`` may arrive as int or str from Telegram; both are accepted when they
    match ``client_id``.

    See: https://core.telegram.org/bots/telegram-login
    """
    jwt = JWT(
        token=id_token,
        config=JWTConfig(
            jwks_url=jwks_uri,
            issuer=TELEGRAM_OIDC_ISSUER,
            # Audience checked below with int/str coercion.
            audience=None,
        ),
    )
    try:
        verified = jwt.verify()
    except Exception as exc:
        raise UnauthorizedError(
            error_code="telegram_auth_invalid",
            detail=f"Telegram id_token verification failed: {exc}",
            message={
                "en": "Telegram login verification failed.",
                "fa": "تأیید ورود تلگرام انجام نشد.",
            },
        ) from exc

    if not verified:
        raise UnauthorizedError(
            error_code="telegram_auth_invalid",
            detail="Telegram id_token verification failed",
            message={
                "en": "Telegram login verification failed.",
                "fa": "تأیید ورود تلگرام انجام نشد.",
            },
        )

    claims = dict(jwt.unverified_payload)
    if not oidc_audience_matches(claims.get("aud"), client_id):
        raise UnauthorizedError(
            error_code="telegram_auth_invalid",
            detail="Telegram id_token audience mismatch",
            message={
                "en": "Telegram login verification failed.",
                "fa": "تأیید ورود تلگرام انجام نشد.",
            },
        )
    telegram_user_id_from_claims(claims)
    return claims


def build_telegram_login_request(
    *, telegram_user_id: str, id_token: str
) -> LoginRequest:
    """Build a LoginRequest after Telegram id_token has been verified."""
    return LoginRequest(
        type=AuthIdentifier.TELEGRAM_ID,
        identifier=telegram_user_id,
        method=AuthSecret.TELEGRAM_TOKEN,
        secret=id_token,
    )
