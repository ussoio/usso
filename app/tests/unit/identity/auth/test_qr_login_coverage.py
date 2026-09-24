"""Focused branch coverage for QR-login session state transitions."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from apps.identity.auth.services import qr_login as qr
from server.exceptions import BadRequestError, ConflictError, UnauthorizedError


def _tenant(uid: str = "tenant-1") -> SimpleNamespace:
    return SimpleNamespace(uid=uid)


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": qr.QR_STATUS_PENDING,
        "tenant_id": "tenant-1",
        "created_at": 100.0,
        "user_id": None,
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_load_session_handles_missing_bytes_and_text() -> None:
    redis = SimpleNamespace(
        get=AsyncMock(
            side_effect=[None, json.dumps(_payload()).encode(), json.dumps(_payload())]
        )
    )
    with patch.object(qr, "redis", redis):
        assert await qr._load_session("missing") is None
        assert (await qr._load_session("bytes"))["tenant_id"] == "tenant-1"
        assert (await qr._load_session("text"))["status"] == qr.QR_STATUS_PENDING


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (None, {"status": qr.QR_STATUS_EXPIRED}),
        (_payload(tenant_id="other"), {"status": qr.QR_STATUS_EXPIRED}),
        (_payload(status=qr.QR_STATUS_CONSUMED), {"status": qr.QR_STATUS_EXPIRED}),
        (_payload(status=qr.QR_STATUS_DENIED), {"status": qr.QR_STATUS_DENIED}),
    ],
)
async def test_status_terminal_and_invalid_states(
    payload: dict[str, object] | None, expected: dict[str, str]
) -> None:
    with (
        patch.object(qr, "_load_session", new=AsyncMock(return_value=payload)),
        patch.object(qr, "_remaining_ttl", return_value=30),
    ):
        assert (
            await qr.get_qr_session_status(tenant=_tenant(), qr_token="token")
            == expected
        )


@pytest.mark.asyncio
async def test_status_expired_deletes_session() -> None:
    redis = SimpleNamespace(delete=AsyncMock())
    with (
        patch.object(qr, "redis", redis),
        patch.object(qr, "_load_session", new=AsyncMock(return_value=_payload())),
        patch.object(qr, "_remaining_ttl", return_value=0),
    ):
        result = await qr.get_qr_session_status(tenant=_tenant(), qr_token="token")
    assert result == {"status": qr.QR_STATUS_EXPIRED}
    redis.delete.assert_awaited_once_with(qr._qr_key("token"))


@pytest.mark.asyncio
async def test_status_pending_includes_remaining_ttl() -> None:
    with (
        patch.object(qr, "_load_session", new=AsyncMock(return_value=_payload())),
        patch.object(qr, "_remaining_ttl", return_value=17),
    ):
        result = await qr.get_qr_session_status(tenant=_tenant(), qr_token="token")
    assert result == {"status": qr.QR_STATUS_PENDING, "expires_in": 17}


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [None, _payload(tenant_id="other")])
async def test_approve_rejects_missing_or_wrong_tenant_session(
    payload: dict[str, object] | None,
) -> None:
    with (
        patch.object(qr, "_load_session", new=AsyncMock(return_value=payload)),
        pytest.raises(BadRequestError) as exc,
    ):
        await qr.approve_qr_session(
            tenant=_tenant(),
            user=SimpleNamespace(uid="user-1", tenant_id="tenant-1"),
            qr_token="token",
        )
    assert exc.value.error_code == "qr_invalid"


@pytest.mark.asyncio
async def test_approve_rejects_expired_session_and_deletes_it() -> None:
    redis = SimpleNamespace(delete=AsyncMock())
    with (
        patch.object(qr, "redis", redis),
        patch.object(qr, "_load_session", new=AsyncMock(return_value=_payload())),
        patch.object(qr, "_remaining_ttl", return_value=0),
        pytest.raises(BadRequestError) as exc,
    ):
        await qr.approve_qr_session(
            tenant=_tenant(),
            user=SimpleNamespace(uid="user-1", tenant_id="tenant-1"),
            qr_token="token",
        )
    assert exc.value.error_code == "qr_expired"
    redis.delete.assert_awaited_once_with(qr._qr_key("token"))


@pytest.mark.asyncio
async def test_approve_rejects_cross_tenant_user() -> None:
    with (
        patch.object(qr, "_load_session", new=AsyncMock(return_value=_payload())),
        patch.object(qr, "_remaining_ttl", return_value=30),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await qr.approve_qr_session(
            tenant=_tenant(),
            user=SimpleNamespace(uid="user-1", tenant_id="other"),
            qr_token="token",
        )
    assert exc.value.error_code == "qr_tenant_mismatch"


@pytest.mark.asyncio
async def test_deny_session_clears_user_and_saves() -> None:
    payload = _payload(user_id="old-user")
    save = AsyncMock()
    with (
        patch.object(qr, "_load_session", new=AsyncMock(return_value=payload)),
        patch.object(qr, "_remaining_ttl", return_value=25),
        patch.object(qr, "_save_session", new=save),
    ):
        result = await qr.approve_qr_session(
            tenant=_tenant(),
            user=SimpleNamespace(uid="user-1", tenant_id="tenant-1"),
            qr_token="token",
            approve=False,
        )
    assert result == {"status": qr.QR_STATUS_DENIED}
    assert payload["user_id"] is None
    save.assert_awaited_once_with("token", payload, ttl=25)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "error_code"),
    [
        (None, "qr_invalid"),
        (_payload(status=qr.QR_STATUS_PENDING), "qr_not_approved"),
        (_payload(status=qr.QR_STATUS_APPROVED, user_id=None), "qr_invalid"),
    ],
)
async def test_claim_rejects_invalid_unapproved_or_userless_session(
    payload: dict[str, object] | None, error_code: str
) -> None:
    with (
        patch.object(qr, "_load_session", new=AsyncMock(return_value=payload)),
        pytest.raises(BadRequestError) as exc,
    ):
        await qr.claim_approved_qr_user(tenant=_tenant(), qr_token="token")
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
async def test_claim_recheck_detects_changed_session() -> None:
    approved = _payload(status=qr.QR_STATUS_APPROVED, user_id="user-1")
    changed = _payload(status=qr.QR_STATUS_CONSUMED, user_id="user-1")
    with (
        patch.object(
            qr, "_load_session", new=AsyncMock(side_effect=[approved, changed])
        ),
        patch.object(qr, "_try_claim_lock", new=AsyncMock(return_value=True)),
        pytest.raises(ConflictError) as exc,
    ):
        await qr.claim_approved_qr_user(tenant=_tenant(), qr_token="token")
    assert exc.value.error_code == "qr_already_claimed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user", [None, SimpleNamespace(uid="user-1", tenant_id="other")]
)
async def test_claim_rejects_missing_or_cross_tenant_user(user: object) -> None:
    approved = _payload(status=qr.QR_STATUS_APPROVED, user_id="user-1")
    with (
        patch.object(
            qr, "_load_session", new=AsyncMock(side_effect=[approved, approved.copy()])
        ),
        patch.object(qr, "_try_claim_lock", new=AsyncMock(return_value=True)),
        patch.object(qr, "_save_session", new=AsyncMock()),
        patch.object(qr.User, "get_item", new=AsyncMock(return_value=user)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await qr.claim_approved_qr_user(tenant=_tenant(), qr_token="token")
    assert exc.value.error_code == "user_not_found"
