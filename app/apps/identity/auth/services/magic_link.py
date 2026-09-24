"""Magic-link token verification helpers."""

import time

from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT, UnverifiedJWT

from server import db
from server.exceptions import ServiceUnavailableError, UnauthorizedError
from utils.outbound import validate_public_url_sync

from ....tenant.models import Tenant
from .basics import get_tenant_url


def magic_link_payload(
    token: str,
    tenant: Tenant,
    url: str | None = None,
) -> tuple[dict, str | bytes | dict | None, str | None, int]:
    """
    Verify magic-link token and return verification context.

    Returns payload with selected verifier material so caller can continue
    login flow using the same trust source (tenant key / trusted IdP).
    """
    jwt = UnverifiedJWT(token=token)
    tenant_url = get_tenant_url(tenant, url)

    key: str | bytes | dict | None = None
    jwks_url: str | None = None
    issuer = jwt.unverified_payload.get("iss")
    if issuer == tenant_url:
        key = tenant.secrets.keys[-1].public_pem
        maximum_age = tenant.config.auth.magic_link_timeout
    elif issuer in tenant.secrets.trusted_identity_providers:
        provider = tenant.secrets.trusted_identity_providers.get(issuer)
        key = provider.key
        jwks_url = provider.jwks_url
        maximum_age = provider.maximum_age
    else:
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Magic link issuer is not trusted",
            message={
                "en": "The sign-in link is invalid or has expired.",
                "fa": "لینک ورود نامعتبر است یا منقضی شده.",
            },
        )

    config_kwargs: dict[str, object] = {
        "maximum_age": maximum_age,
        "issuer": issuer,
        "audience": tenant_url,
    }
    if jwks_url:
        validate_public_url_sync(jwks_url)
        config_kwargs["jwks_url"] = jwks_url
    else:
        config_kwargs["key"] = key

    jwt = JWT(token=token, config=JWTConfig(**config_kwargs))
    jwt.verify()
    return jwt.payload, key, jwks_url, maximum_age


async def consume_magic_link(payload: dict, tenant: Tenant) -> None:
    """Atomically consume a verified magic link so it cannot be replayed."""
    jti = payload.get("jti")
    exp = int(payload.get("exp") or 0)
    if not isinstance(jti, str) or not jti or exp <= int(time.time()):
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Magic link is invalid or expired",
            message={
                "en": "The sign-in link is invalid or has expired.",
                "fa": "لینک ورود نامعتبر است یا منقضی شده.",
            },
        )
    if db.redis is None:
        raise ServiceUnavailableError(
            error_code="magic_link_store_unavailable",
            detail="Magic-link replay protection is unavailable",
        )
    try:
        acquired = await db.redis.set(
            f"usso:magic-link:{tenant.uid}:{jti}",
            "1",
            nx=True,
            ex=max(1, exp - int(time.time())),
        )
    except Exception as exc:
        raise ServiceUnavailableError(
            error_code="magic_link_store_unavailable",
            detail="Magic-link replay protection is unavailable",
        ) from exc
    if not acquired:
        raise UnauthorizedError(
            error_code="magic_link_already_used",
            detail="Magic link has already been used",
            message={
                "en": "This sign-in link has already been used.",
                "fa": "این لینک ورود قبلاً استفاده شده است.",
            },
        )
