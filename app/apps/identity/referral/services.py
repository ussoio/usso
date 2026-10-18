"""Referral business logic and tenant webhook notifications."""

from __future__ import annotations

import asyncio
import logging
from asyncio import sleep
from datetime import datetime
from typing import TYPE_CHECKING

import httpx
from fastapi_mongo_base.utils import timezone

from utils.outbound import validate_public_url

if TYPE_CHECKING:
    from apps.identity.user.models import User
    from apps.tenant.models import Tenant

    from .models import ReferralCode

logger = logging.getLogger(__name__)

REFERRAL_REGISTERED_EVENT = "referral_registered"
REFERRAL_USED_EVENT = "referral.used"
USER_CREATED_EVENT = "user.created"


async def consume_referral_code(referral: ReferralCode) -> bool:
    """Atomically reserve one use without allowing ``max_usage`` overflow."""
    now = datetime.now(timezone.tz)
    result = (
        await type(referral)
        .get_pymongo_collection()
        .update_one(
            {
                "_id": referral.id,
                "tenant_id": referral.tenant_id,
                "is_active": True,
                "$and": [
                    {
                        "$or": [
                            {"expires_at": {"$exists": False}},
                            {"expires_at": None},
                            {"expires_at": {"$gt": now}},
                        ]
                    },
                    {
                        "$expr": {
                            "$or": [
                                {"$eq": [{"$ifNull": ["$max_usage", None]}, None]},
                                {
                                    "$lt": [
                                        {"$ifNull": ["$usage_count", 0]},
                                        "$max_usage",
                                    ]
                                },
                            ]
                        }
                    },
                ],
            },
            {"$inc": {"usage_count": 1}},
        )
    )
    if result.modified_count != 1:
        return False
    referral.usage_count += 1
    return True


async def release_referral_code(referral: ReferralCode) -> None:
    """Release a reservation when user creation fails before registration."""
    result = (
        await type(referral)
        .get_pymongo_collection()
        .update_one(
            {
                "_id": referral.id,
                "tenant_id": referral.tenant_id,
                "usage_count": {"$gt": 0},
            },
            {"$inc": {"usage_count": -1}},
        )
    )
    if result.modified_count == 1:
        referral.usage_count = max(0, referral.usage_count - 1)


def extract_referral_code(raw: str | None) -> str | None:
    """
    Normalize an invite code or invite link into a bare referral code.

    Accepts:
    - bare codes: ``ABC123``
    - query links: ``https://app/x?referral_code=ABC`` / ``?ref=`` / ``?invite=``
    - path links: ``/invite/ABC`` / ``/r/ABC`` / ``/referral/ABC``
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None

    from urllib.parse import parse_qs, urlparse

    looks_like_url = "://" in value or value.startswith("/") or "?" in value
    if not looks_like_url:
        return value

    parsed = urlparse(value if "://" in value else f"https://local{value}")
    query = parse_qs(parsed.query)
    for key in ("referral_code", "ref", "invite", "code"):
        values = query.get(key) or []
        if values and values[0].strip():
            return values[0].strip()

    parts = [part for part in parsed.path.split("/") if part]
    for i, part in enumerate(parts):
        if part in {"invite", "r", "referral", "ref"} and i + 1 < len(parts):
            return parts[i + 1]
    return parts[-1] if parts else None


# Rewards ride on these calls, so a brief outage of the receiver must not lose
# them. In-process retry only: a restart drops pending retries.
WEBHOOK_ATTEMPTS = 4
WEBHOOK_BACKOFF_SECONDS = 2.0


def _is_transient(exc: Exception) -> bool:
    """Retry network errors, timeouts, 5xx and 429; never other client errors."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status >= 500 or status == 429
    return isinstance(exc, httpx.TransportError)


async def _post_webhook(
    *,
    url: str,
    headers: dict[str, str] | None,
    payload: dict,
) -> None:
    for attempt in range(1, WEBHOOK_ATTEMPTS + 1):
        try:
            await validate_public_url(url)
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(url, json=payload, headers=headers or {})
                response.raise_for_status()
        except Exception as exc:
            if attempt == WEBHOOK_ATTEMPTS or not _is_transient(exc):
                logger.exception(
                    "Webhook failed for %s (attempt %d/%d)",
                    url,
                    attempt,
                    WEBHOOK_ATTEMPTS,
                )
                return
            logger.warning(
                "Webhook to %s failed (attempt %d/%d): %s; retrying",
                url,
                attempt,
                WEBHOOK_ATTEMPTS,
                exc,
            )
            await sleep(WEBHOOK_BACKOFF_SECONDS * 3 ** (attempt - 1))
        else:
            return


_webhook_tasks: set[asyncio.Task] = set()


def dispatch_tenant_webhooks(
    *,
    tenant: Tenant,
    event: str,
    payload: dict,
) -> None:
    """Fire matching tenant webhooks best-effort (non-blocking)."""
    webhooks = getattr(getattr(tenant, "config", None), "integration", None)
    if webhooks is None:
        return
    for hook in webhooks.webhooks or []:
        if event not in (hook.events or []):
            continue
        task = asyncio.create_task(
            _post_webhook(
                url=str(hook.url),
                headers=hook.headers,
                payload={"event": event, **payload},
            )
        )
        _webhook_tasks.add(task)
        task.add_done_callback(_webhook_tasks.discard)


def on_referral_registration(
    *,
    tenant: Tenant,
    referral: ReferralCode,
    invitee: User,
) -> None:
    """Notify configured webhooks after a successful invited registration."""
    dispatch_tenant_webhooks(
        tenant=tenant,
        event=REFERRAL_REGISTERED_EVENT,
        payload={
            "tenant_id": tenant.uid,
            "referrer_user_id": referral.user_id,
            "invitee_user_id": invitee.uid,
            "referral_code": referral.code,
        },
    )
    body = {
        "tenant_id": tenant.uid,
        "referral_code": referral.code,
        "referrer_user_id": referral.user_id,
        "invitee_user_id": invitee.uid,
        "usage_count": referral.usage_count,
    }
    dispatch_tenant_webhooks(tenant=tenant, event=REFERRAL_USED_EVENT, payload=body)
    dispatch_tenant_webhooks(
        tenant=tenant,
        event=USER_CREATED_EVENT,
        payload={
            "tenant_id": tenant.uid,
            "user_id": invitee.uid,
            "referral_code": referral.code,
            "referrer_user_id": referral.user_id,
        },
    )
