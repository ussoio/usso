"""Unit tests for QR login helpers and passkey challenge keys."""

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from apps.identity.auth.services import qr_login as qr
from apps.identity.user import credential_services as creds
from server.exceptions import BadRequestError, ConflictError
from utils import texttools


class FakeRedis:
    """Minimal async Redis stub with SET NX support."""

    def __init__(self) -> None:
        """Initialize empty key store."""
        self.store: dict[str, str] = {}

    async def set(
        self,
        key: str,
        value: str,
        ex: int | None = None,
        nx: bool = False,
    ) -> bool | None:
        """Set a key; with nx=True only if missing."""
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def get(self, key: str) -> str | None:
        """Get a key value."""
        return self.store.get(key)

    async def delete(self, key: str) -> None:
        """Delete a key."""
        self.store.pop(key, None)


def test_passkey_auth_challenge_key_is_scoped() -> None:
    """Auth challenges are keyed per challenge bytes, not a global key."""
    challenge = b"abc123-challenge"
    key = creds._passkey_auth_challenge_key(challenge)
    assert key.startswith("passkey:auth:")
    assert texttools.base64url_encode(challenge) in key


@pytest.mark.asyncio
async def test_create_and_approve_qr_session() -> None:
    """QR session moves pending → approved for the same tenant user."""
    redis = FakeRedis()
    tenant = SimpleNamespace(
        uid="t1",
        get_frontend_url=lambda _route: "https://sso.example.test/login",
    )
    user = SimpleNamespace(uid="u1", tenant_id="t1")

    with mock.patch("apps.identity.auth.services.qr_login.redis", redis):
        created = await qr.create_qr_session(tenant=tenant)
        assert created["qr_token"]
        assert "qr_token=" in created["qr_payload"]

        approved = await qr.approve_qr_session(
            tenant=tenant, user=user, qr_token=created["qr_token"]
        )
        assert approved["status"] == qr.QR_STATUS_APPROVED

        status = await qr.get_qr_session_status(
            tenant=tenant, qr_token=created["qr_token"]
        )
        assert status["status"] == qr.QR_STATUS_APPROVED
        assert status["user_id"] == "u1"


@pytest.mark.asyncio
async def test_approve_qr_session_twice_conflicts() -> None:
    """Second approve on the same token is rejected."""
    redis = FakeRedis()
    tenant = SimpleNamespace(
        uid="t1",
        get_frontend_url=lambda _route: "https://sso.example.test/login",
    )
    user = SimpleNamespace(uid="u1", tenant_id="t1")

    with mock.patch("apps.identity.auth.services.qr_login.redis", redis):
        created = await qr.create_qr_session(tenant=tenant)
        await qr.approve_qr_session(
            tenant=tenant, user=user, qr_token=created["qr_token"]
        )
        with pytest.raises(ConflictError) as exc:
            await qr.approve_qr_session(
                tenant=tenant, user=user, qr_token=created["qr_token"]
            )
        assert exc.value.error_code == "qr_already_resolved"


@pytest.mark.asyncio
async def test_claim_approved_qr_user_consumes_session() -> None:
    """Claiming an approved session returns the user and consumes the token."""
    redis = FakeRedis()
    tenant = SimpleNamespace(
        uid="t1",
        get_frontend_url=lambda _route: "https://sso.example.test/login",
    )
    user = SimpleNamespace(uid="u1", tenant_id="t1")

    with (
        mock.patch("apps.identity.auth.services.qr_login.redis", redis),
        mock.patch(
            "apps.identity.auth.services.qr_login.User.get_item",
            new_callable=mock.AsyncMock,
            return_value=user,
        ),
    ):
        created = await qr.create_qr_session(tenant=tenant)
        await qr.approve_qr_session(
            tenant=tenant, user=user, qr_token=created["qr_token"]
        )
        claimed = await qr.claim_approved_qr_user(
            tenant=tenant, qr_token=created["qr_token"]
        )
        assert claimed is user

        status = await qr.get_qr_session_status(
            tenant=tenant, qr_token=created["qr_token"]
        )
        assert status["status"] == qr.QR_STATUS_EXPIRED

        with pytest.raises(BadRequestError):
            await qr.claim_approved_qr_user(tenant=tenant, qr_token=created["qr_token"])


@pytest.mark.asyncio
async def test_claim_approved_qr_user_is_atomic() -> None:
    """Only the first concurrent claimer wins the SET NX lock."""
    redis = FakeRedis()
    tenant = SimpleNamespace(
        uid="t1",
        get_frontend_url=lambda _route: "https://sso.example.test/login",
    )
    user = SimpleNamespace(uid="u1", tenant_id="t1")

    with (
        mock.patch("apps.identity.auth.services.qr_login.redis", redis),
        mock.patch(
            "apps.identity.auth.services.qr_login.User.get_item",
            new_callable=mock.AsyncMock,
            return_value=user,
        ),
    ):
        created = await qr.create_qr_session(tenant=tenant)
        token = created["qr_token"]
        await qr.approve_qr_session(tenant=tenant, user=user, qr_token=token)

        first = await qr.claim_approved_qr_user(tenant=tenant, qr_token=token)
        assert first is user

        # Simulate another poller racing after status was approved: lock already held.
        # Re-seed approved payload but keep claim lock.
        redis.store[qr._qr_key(token)] = json.dumps({
            "status": qr.QR_STATUS_APPROVED,
            "tenant_id": "t1",
            "created_at": 0,
            "user_id": "u1",
        })
        with pytest.raises(ConflictError) as exc:
            await qr.claim_approved_qr_user(tenant=tenant, qr_token=token)
        assert exc.value.error_code == "qr_already_claimed"
