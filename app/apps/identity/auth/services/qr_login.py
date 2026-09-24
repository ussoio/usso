"""WhatsApp-style QR session login (desktop shows QR, phone approves)."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

from apps.identity.user.models import User
from apps.tenant.models import Tenant
from server.db import redis
from server.exceptions import BadRequestError, ConflictError, UnauthorizedError

QR_SESSION_TTL = 120
QR_STATUS_PENDING = "pending"
QR_STATUS_APPROVED = "approved"
QR_STATUS_CONSUMED = "consumed"
QR_STATUS_EXPIRED = "expired"
QR_STATUS_DENIED = "denied"


def _qr_key(qr_token: str) -> str:
    return f"qr:session:{qr_token}"


def _claim_key(qr_token: str) -> str:
    return f"qr:claim:{qr_token}"


async def create_qr_session(*, tenant: Tenant) -> dict[str, Any]:
    """Create a pending QR login session for the desktop browser."""
    qr_token = secrets.token_urlsafe(24)
    payload = {
        "status": QR_STATUS_PENDING,
        "tenant_id": tenant.uid,
        "created_at": time.time(),
        "user_id": None,
    }
    await redis.set(_qr_key(qr_token), json.dumps(payload), ex=QR_SESSION_TTL)
    frontend = tenant.get_frontend_url("login")
    qr_payload = f"{frontend}?qr_token={qr_token}"
    return {
        "qr_token": qr_token,
        "expires_in": QR_SESSION_TTL,
        "qr_payload": qr_payload,
    }


async def _load_session(qr_token: str) -> dict[str, Any] | None:
    raw = await redis.get(_qr_key(qr_token))
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    return json.loads(raw)


async def _save_session(qr_token: str, payload: dict[str, Any], *, ttl: int) -> None:
    await redis.set(_qr_key(qr_token), json.dumps(payload), ex=max(ttl, 1))


def _remaining_ttl(payload: dict[str, Any]) -> int:
    created = float(payload.get("created_at") or time.time())
    return max(0, int(QR_SESSION_TTL - (time.time() - created)))


async def get_qr_session_status(*, tenant: Tenant, qr_token: str) -> dict[str, Any]:
    """Return current QR session status for desktop polling."""
    payload = await _load_session(qr_token)
    if not payload or payload.get("tenant_id") != tenant.uid:
        return {"status": QR_STATUS_EXPIRED}
    ttl = _remaining_ttl(payload)
    if ttl <= 0:
        await redis.delete(_qr_key(qr_token))
        return {"status": QR_STATUS_EXPIRED}
    status = payload.get("status") or QR_STATUS_PENDING
    if status == QR_STATUS_CONSUMED:
        return {"status": QR_STATUS_EXPIRED}
    if status == QR_STATUS_DENIED:
        return {"status": QR_STATUS_DENIED}
    if status == QR_STATUS_APPROVED:
        return {
            "status": QR_STATUS_APPROVED,
            "user_id": payload.get("user_id"),
        }
    return {"status": QR_STATUS_PENDING, "expires_in": ttl}


async def approve_qr_session(
    *,
    tenant: Tenant,
    user: User,
    qr_token: str,
    approve: bool = True,
) -> dict[str, Any]:
    """Phone (logged-in user) approves or denies a pending QR session."""
    payload = await _load_session(qr_token)
    if not payload or payload.get("tenant_id") != tenant.uid:
        raise BadRequestError(
            error_code="qr_invalid",
            detail="QR session expired or invalid",
            message={
                "en": "QR session expired or invalid.",
                "fa": "نشست QR نامعتبر است یا منقضی شده.",
            },
        )
    ttl = _remaining_ttl(payload)
    if ttl <= 0:
        await redis.delete(_qr_key(qr_token))
        raise BadRequestError(
            error_code="qr_expired",
            detail="QR session expired",
            message={
                "en": "QR session expired.",
                "fa": "مهلت ورود با QR تمام شده.",
            },
        )
    if payload.get("status") != QR_STATUS_PENDING:
        raise ConflictError(
            error_code="qr_already_resolved",
            detail="QR session already resolved",
            message={
                "en": "This QR code was already used.",
                "fa": "این کد QR قبلاً استفاده شده.",
            },
        )
    if user.tenant_id != tenant.uid:
        raise UnauthorizedError(
            error_code="qr_tenant_mismatch",
            detail="User tenant mismatch",
            message={
                "en": "You cannot approve this QR login.",
                "fa": "اجازه تأیید این ورود را ندارید.",
            },
        )

    payload["status"] = QR_STATUS_APPROVED if approve else QR_STATUS_DENIED
    payload["user_id"] = user.uid if approve else None
    await _save_session(qr_token, payload, ttl=ttl)
    return {"status": payload["status"]}


async def _try_claim_lock(qr_token: str) -> bool:
    """Acquire a one-time claim lock (SET NX). Returns True if this caller won."""
    result = await redis.set(_claim_key(qr_token), "1", nx=True, ex=60)
    return bool(result)


async def claim_approved_qr_user(*, tenant: Tenant, qr_token: str) -> User:
    """
    Atomically claim an approved QR session for desktop token issuance.

    Uses Redis SET NX so only one concurrent poller can consume the session.
    """
    payload = await _load_session(qr_token)
    if not payload or payload.get("tenant_id") != tenant.uid:
        raise BadRequestError(
            error_code="qr_invalid",
            detail="QR session expired or invalid",
            message={
                "en": "QR session expired or invalid.",
                "fa": "نشست QR نامعتبر است یا منقضی شده.",
            },
        )
    if payload.get("status") != QR_STATUS_APPROVED:
        raise BadRequestError(
            error_code="qr_not_approved",
            detail="QR session is not approved",
            message={
                "en": "QR login is not approved yet.",
                "fa": "ورود با QR هنوز تأیید نشده.",
            },
        )
    user_id = payload.get("user_id")
    if not user_id:
        raise BadRequestError(
            error_code="qr_invalid",
            detail="QR session missing user",
            message={
                "en": "QR session is invalid.",
                "fa": "نشست QR نامعتبر است.",
            },
        )

    if not await _try_claim_lock(qr_token):
        raise ConflictError(
            error_code="qr_already_claimed",
            detail="QR session already claimed",
            message={
                "en": "This QR login was already completed.",
                "fa": "این ورود با QR قبلاً تکمیل شده.",
            },
        )

    # Re-check after winning the lock (another path may have expired the key).
    payload = await _load_session(qr_token)
    if (
        not payload
        or payload.get("tenant_id") != tenant.uid
        or payload.get("status") != QR_STATUS_APPROVED
        or payload.get("user_id") != user_id
    ):
        raise ConflictError(
            error_code="qr_already_claimed",
            detail="QR session already claimed",
            message={
                "en": "This QR login was already completed.",
                "fa": "این ورود با QR قبلاً تکمیل شده.",
            },
        )

    payload["status"] = QR_STATUS_CONSUMED
    await _save_session(qr_token, payload, ttl=30)

    user = await User.get_item(uid=user_id, tenant_id=tenant.uid)
    if not user or user.tenant_id != tenant.uid:
        raise UnauthorizedError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )
    return user
