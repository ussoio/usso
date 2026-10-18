"""API key services."""

import base64
import hashlib
import logging
import secrets
import time
import uuid
from datetime import datetime

from aiocache import cached
from fastapi_mongo_base.utils import timezone
from usso import UserData

from server.db import redis
from server.exceptions import ForbiddenError, TooManyRequestsError, UnauthorizedError
from utils.hasher import PasswordHasherService
from utils.request_context import client_ip_var, user_agent_var

from .models import APIKey

CLIENT_SECRET_BYTES = 32
logger = logging.getLogger(__name__)

# In-memory fallback when Redis is unavailable: key -> (window_start, count)
_rate_buckets: dict[str, tuple[int, int]] = {}


def b64_encode_uuid_strip(u: uuid.UUID | None = None) -> str:
    """Encode UUID to base64-url string without padding."""
    if u is None:
        u = uuid.uuid4()
    b = u.bytes
    b64 = base64.urlsafe_b64encode(b).decode().rstrip("=")
    return b64


def b64_decode_uuid_strip(encoded: str) -> str:
    """
    Decode a base64-url encoded UUID string without padding back to a UUID object.

    Example input: 'mJzAf2vFR3apkrFt_5shgQ'.
    """
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    byte_data = base64.urlsafe_b64decode(padded)
    return str(uuid.UUID(bytes=byte_data))


def generate_client_secret(*, length: int = CLIENT_SECRET_BYTES) -> str:
    """Generate a high-entropy OAuth client_secret."""
    return secrets.token_urlsafe(length)


def generate_api_key(uid: uuid.UUID | None = None, secret_length: int = 32) -> dict:
    """
    Generate a new API key.

    Output:
    - api_key: <generated-id>.<random-secret>
    - api_key_pattern: uak_abcd***
    - secret: <random-secret>
    - hashed_key: a
    """
    bid = b64_encode_uuid_strip(uid)
    uid_str = b64_decode_uuid_strip(bid)
    secret = secrets.token_urlsafe(secret_length)
    full_api_key = f"uak-{bid}.{secret}"
    api_key_pattern = full_api_key[:10] + "*" * (len(full_api_key) - 10)

    hashed_key = PasswordHasherService().hash_password(full_api_key)

    return {
        "uid": uid_str,
        "secret_length": secret_length,
        "api_key_pattern": api_key_pattern,
        "api_key": full_api_key,
        "hashed_key": hashed_key,
    }


def _api_key_cache_key(_func: object, api_key: str, **_kwargs: object) -> str:
    """Cache by the complete presented credential, never its public UID alone."""
    return "api-key:" + hashlib.sha256(api_key.encode()).hexdigest()


def _extract_api_key_uid(api_key: str) -> str:
    """Validate the public API-key envelope and return its decoded UUID."""
    if not isinstance(api_key, str) or not api_key.startswith("uak-"):
        raise ValueError("invalid API key")
    if len(api_key) > 512:
        raise ValueError("invalid API key")
    dot_pos = api_key.find(".", 4)
    if dot_pos <= 4 or dot_pos == len(api_key) - 1:
        raise ValueError("invalid API key")
    return b64_decode_uuid_strip(api_key[4:dot_pos])


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.tz)
    return value


def _validate_api_key_state(db_key: APIKey) -> None:
    """Reject inactive, revoked, or expired API keys."""
    if not db_key.is_active:
        raise UnauthorizedError(
            error_code="api_key_inactive",
            detail="API key is inactive.",
            message={
                "en": "API key is inactive.",
                "fa": "کلید دسترسی غیرفعال است.",
            },
        )

    if db_key.revoked is not None:
        raise UnauthorizedError(
            error_code="api_key_revoked",
            detail="API key has been revoked.",
            message={
                "en": "API key has been revoked.",
                "fa": "کلید دسترسی لغو شده است.",
            },
        )

    if db_key.expires_at is not None:
        expires_at = _ensure_aware(db_key.expires_at)
        if expires_at <= datetime.now(timezone.tz):
            raise UnauthorizedError(
                error_code="api_key_expired",
                detail="API key has expired.",
                message={
                    "en": "API key has expired.",
                    "fa": "کلید دسترسی منقضی شده است.",
                },
            )


def enforce_api_key_spend_limit(db_key: APIKey) -> None:
    """Reject a key whose recorded spend has reached its spend limit."""
    limit = getattr(db_key, "spend_limit", None)
    if limit is None:
        return
    if float(getattr(db_key, "spend_usage", 0.0) or 0.0) >= limit:
        raise ForbiddenError(
            error_code="api_key_spend_limit_exceeded",
            detail="API key spend limit exceeded.",
            message={
                "en": "API key spend limit exceeded.",
                "fa": "سقف هزینهٔ کلید دسترسی پر شده است.",
            },
        )


async def record_api_key_spend(uid: str, amount: float) -> None:
    """Add ``amount`` to the key's spend and drop cached verification."""
    await APIKey.get_pymongo_collection().update_one(
        {"uid": uid, "is_deleted": False}, {"$inc": {"spend_usage": amount}}
    )
    await invalidate_api_key_cache(uid=uid)


def enforce_api_key_ip_whitelist(db_key: APIKey, *, client_ip: str | None) -> None:
    """Reject requests whose client IP is not on the key allowlist (if set)."""
    whitelist = list(db_key.ip_whitelist or [])
    if not whitelist:
        return
    if not client_ip or client_ip not in whitelist:
        raise ForbiddenError(
            error_code="api_key_ip_denied",
            detail="API key is not allowed from this IP address.",
            message={
                "en": "API key is not allowed from this IP address.",
                "fa": "استفاده از این کلید دسترسی از این IP مجاز نیست.",
            },
        )


def _api_key_rate_limited_error() -> TooManyRequestsError:
    return TooManyRequestsError(
        error_code="api_key_rate_limited",
        detail="API key rate limit exceeded.",
        message={
            "en": "API key rate limit exceeded.",
            "fa": "محدودیت نرخ استفاده از کلید دسترسی رد شده است.",
        },
    )


async def enforce_api_key_rate_limit(db_key: APIKey) -> None:
    """
    Enforce per-key rate limit.

    ``rate_limit`` shape: ``{"requests": int, "window_seconds": int}``.
    Empty / missing config means unlimited.
    """
    cfg = dict(db_key.rate_limit or {})
    max_requests = int(cfg.get("requests") or cfg.get("max_requests") or 0)
    window = int(cfg.get("window_seconds") or cfg.get("window") or 60)
    if max_requests <= 0:
        return

    bucket_key = f"usso:api_key_rate:{db_key.uid}:{window}"
    now = int(time.time())

    if redis is not None:
        try:
            count = await redis.incr(bucket_key)
            if count == 1:
                await redis.expire(bucket_key, window)
        except Exception:
            logger.exception("API key Redis rate limit failed; using memory")
        else:
            if count > max_requests:
                raise _api_key_rate_limited_error()
            return

    start, count = _rate_buckets.get(bucket_key, (now, 0))
    if now - start >= window:
        start, count = now, 0
    count += 1
    _rate_buckets[bucket_key] = (start, count)
    if count > max_requests:
        raise _api_key_rate_limited_error()


async def record_api_key_usage(
    db_key: APIKey,
    *,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Persist last-use stats (best-effort; does not block auth on failure)."""
    now = datetime.now(timezone.tz)
    try:
        await APIKey.get_pymongo_collection().update_one(
            {"uid": db_key.uid, "is_deleted": False},
            {
                "$inc": {"usage_count": 1},
                "$set": {
                    "last_used_at": now,
                    **({"last_ip": client_ip} if client_ip else {}),
                    **({"last_user_agent": user_agent} if user_agent else {}),
                },
            },
        )
        db_key.last_used_at = now
        db_key.usage_count = int(getattr(db_key, "usage_count", 0) or 0) + 1
        if client_ip:
            db_key.last_ip = client_ip
        if user_agent:
            db_key.last_user_agent = user_agent
    except Exception:
        logger.exception("Failed to record API key usage for %s", db_key.uid)


async def verify_api_key(api_key: str) -> tuple[str, APIKey]:
    """Verify an API key and return the key data."""
    try:
        api_uid = _extract_api_key_uid(api_key)
    except (TypeError, ValueError):
        raise UnauthorizedError(
            error_code="api_key_invalid",
            detail="Invalid API key.",
            message={
                "en": "Invalid API key.",
                "fa": "کلید دسترسی نامعتبر است.",
            },
        ) from None

    db_keys: list[APIKey] = await APIKey.get_query(uid=api_uid).to_list()

    if not db_keys:
        raise UnauthorizedError(
            error_code="api_key_not_found",
            detail="API key not found",
            message={
                "en": "API key not found",
                "fa": "کلید دسترسی پیدا نشد.",
            },
        )

    db_key = db_keys[0]

    if not PasswordHasherService().verify_password(db_key.hashed_key, api_key):
        raise UnauthorizedError(
            error_code="api_key_invalid",
            detail="Invalid API key.",
            message={
                "en": "Invalid API key.",
                "fa": "کلید دسترسی نامعتبر است.",
            },
        )

    _validate_api_key_state(db_key)
    enforce_api_key_spend_limit(db_key)

    return api_uid, db_key


def api_key_to_user_data(db_key: APIKey, *, jti: str | None = None) -> UserData:
    """Build UserData where sub is the API key identity (not the owner user)."""
    return UserData(
        jti=jti or db_key.uid,
        iat=int(db_key.created_at.timestamp()) if db_key.created_at else None,
        sub=db_key.uid,
        tenant_id=db_key.tenant_id,
        workspace_id=db_key.workspace_id,
        scopes=db_key.scopes,
        amr=["api_key"],
        user_id=db_key.user_id,
        created_by=db_key.created_by,
        sub_type="api_key",
        spend_limit=getattr(db_key, "spend_limit", None),
        spend_usage=getattr(db_key, "spend_usage", 0.0),
    )


@cached(ttl=60, key_builder=_api_key_cache_key)
async def _verify_api_key_cached(api_key: str) -> tuple[str, str]:
    """Cache credential verification; returns (uid, tenant_id) then reloads key."""
    uid, db_key = await verify_api_key(api_key=api_key)
    return uid, db_key.uid


async def get_api_key_data(api_key: str, *, tenant_id: str | None = None) -> UserData:
    """Get principal data from API key (sub = api_key.uid)."""
    uid, key_uid = await _verify_api_key_cached(api_key)
    db_keys = await APIKey.get_query(uid=key_uid).to_list()
    if not db_keys:
        raise UnauthorizedError(
            error_code="api_key_not_found",
            detail="API key not found",
            message={
                "en": "API key not found",
                "fa": "کلید دسترسی پیدا نشد.",
            },
        )
    db_key = db_keys[0]
    _validate_api_key_state(db_key)
    enforce_api_key_spend_limit(db_key)
    if tenant_id is not None and db_key.tenant_id != tenant_id:
        raise UnauthorizedError(
            error_code="api_key_not_found",
            detail="API key not found",
            message={
                "en": "API key not found",
                "fa": "کلید دسترسی پیدا نشد.",
            },
        )

    client_ip = client_ip_var.get()
    user_agent = user_agent_var.get()
    enforce_api_key_ip_whitelist(db_key, client_ip=client_ip)
    await enforce_api_key_rate_limit(db_key)
    await record_api_key_usage(db_key, client_ip=client_ip, user_agent=user_agent)

    return api_key_to_user_data(db_key, jti=uid)


async def invalidate_api_key_cache(
    *, api_key: str | None = None, uid: str | None = None
) -> None:
    """Drop cached user data for a deleted or revoked API key."""
    if api_key is not None:
        await _verify_api_key_cached.cache.delete(_api_key_cache_key(None, api_key))
    elif uid is not None:
        # The cache deliberately cannot be addressed by the public UID: doing
        # so caused every secret sharing that UID to collide. Revocations are
        # rare, so clearing this small short-lived cache is the safe tradeoff.
        await _verify_api_key_cached.cache.clear()


def verify_client_secret(*, db_key: APIKey, client_secret: str) -> bool:
    """Verify OAuth client_secret against the stored hash."""
    if not db_key.hashed_client_secret or not client_secret:
        return False
    return PasswordHasherService().verify_password(
        db_key.hashed_client_secret, client_secret
    )
