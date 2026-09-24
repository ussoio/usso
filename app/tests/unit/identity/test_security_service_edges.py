"""Failure-path coverage for replay and agent authentication controls."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.agent import services as agent_services
from apps.identity.auth.services import magic_link
from apps.identity.auth.services import token as token_services
from server import db
from server.exceptions import ServiceUnavailableError, UnauthorizedError


@pytest.mark.asyncio
async def test_magic_link_rejects_invalid_payload_and_missing_store() -> None:
    tenant = SimpleNamespace(uid="tenant")
    with pytest.raises(UnauthorizedError, match="invalid or expired"):
        await magic_link.consume_magic_link({}, tenant)

    with (
        patch.object(db, "redis", None),
        pytest.raises(ServiceUnavailableError) as unavailable,
    ):
        await magic_link.consume_magic_link(
            {"jti": "valid", "exp": int(time.time()) + 60}, tenant
        )
    assert unavailable.value.error_code == "magic_link_store_unavailable"


@pytest.mark.asyncio
async def test_magic_link_store_failure_replay_and_success() -> None:
    payload = {"jti": "valid", "exp": int(time.time()) + 60}
    tenant = SimpleNamespace(uid="tenant")

    failing = SimpleNamespace(set=AsyncMock(side_effect=RuntimeError("redis down")))
    with (
        patch.object(db, "redis", failing),
        pytest.raises(ServiceUnavailableError),
    ):
        await magic_link.consume_magic_link(payload, tenant)

    replayed = SimpleNamespace(set=AsyncMock(return_value=False))
    with (
        patch.object(db, "redis", replayed),
        pytest.raises(UnauthorizedError) as replay,
    ):
        await magic_link.consume_magic_link(payload, tenant)
    assert replay.value.error_code == "magic_link_already_used"

    available = SimpleNamespace(set=AsyncMock(return_value=True))
    with patch.object(db, "redis", available):
        await magic_link.consume_magic_link(payload, tenant)
    available.set.assert_awaited_once()


def test_agent_client_secret_and_tenant_guards() -> None:
    assert not agent_services.verify_agent_client_secret(
        agent=SimpleNamespace(hashed_client_secret=None), client_secret="secret"
    )
    assert not agent_services.verify_agent_client_secret(
        agent=SimpleNamespace(hashed_client_secret="hash"), client_secret=""
    )
    with pytest.raises(UnauthorizedError) as mismatch:
        agent_services._enforce_agent_tenant({"tenant_id": "other"}, tenant_id="tenant")
    assert mismatch.value.error_code == "tenant_mismatch"


@pytest.mark.asyncio
async def test_agent_ttl_validation_and_ceiling() -> None:
    with pytest.raises(UnauthorizedError) as invalid:
        await agent_services._enforce_agent_jwt_ttl(
            payload={"iat": 10, "exp": 9}, tenant_id="tenant"
        )
    assert invalid.value.error_code == "invalid_token"

    tenant = SimpleNamespace(
        config=SimpleNamespace(token=SimpleNamespace(access_timeout=5))
    )
    with (
        patch.object(
            agent_services.Tenant,
            "get_by_uid",
            new=AsyncMock(return_value=tenant),
        ),
        pytest.raises(UnauthorizedError) as exceeded,
    ):
        await agent_services._enforce_agent_jwt_ttl(
            payload={"iat": 10, "exp": 20}, tenant_id="tenant"
        )
    assert exceeded.value.error_code == "agent_token_ttl_exceeded"

    with patch.object(
        agent_services.Tenant,
        "get_by_uid",
        new=AsyncMock(return_value=None),
    ):
        await agent_services._enforce_agent_jwt_ttl(
            payload={"iat": 10, "exp": 20}, tenant_id="tenant"
        )


@pytest.mark.asyncio
async def test_agent_assertion_store_guards() -> None:
    assertion = SimpleNamespace(
        jti="assertion-identifier",
        tenant_id="tenant",
        exp=int(time.time()) + 60,
    )
    with (
        patch.object(db, "redis", None),
        pytest.raises(ServiceUnavailableError),
    ):
        await agent_services._consume_agent_assertion(
            assertion=assertion, agent_id="agent"
        )

    failing = SimpleNamespace(set=AsyncMock(side_effect=RuntimeError("down")))
    with (
        patch.object(db, "redis", failing),
        pytest.raises(ServiceUnavailableError),
    ):
        await agent_services._consume_agent_assertion(
            assertion=assertion, agent_id="agent"
        )

    replayed = SimpleNamespace(set=AsyncMock(return_value=False))
    with (
        patch.object(db, "redis", replayed),
        pytest.raises(UnauthorizedError) as replay,
    ):
        await agent_services._consume_agent_assertion(
            assertion=assertion, agent_id="agent"
        )
    assert replay.value.error_code == "agent_assertion_already_used"


def _agent_query(agent: object) -> MagicMock:
    return MagicMock(first_or_none=AsyncMock(return_value=agent))


@pytest.mark.asyncio
async def test_agent_auth_rejects_missing_unknown_and_inactive_agent() -> None:
    with (
        patch.object(
            agent_services,
            "UnverifiedJWT",
            return_value=SimpleNamespace(unverified_payload={}, unverified_header={}),
        ),
        pytest.raises(UnauthorizedError) as missing,
    ):
        await agent_services.agent_auth("token", tenant_id="tenant")
    assert missing.value.error_code == "invalid_token"

    with (
        patch.object(
            agent_services,
            "UnverifiedJWT",
            return_value=SimpleNamespace(
                unverified_payload={"iss": "agent"},
                unverified_header={},
            ),
        ),
        patch.object(
            agent_services.models.Agent,
            "get_query",
            return_value=SimpleNamespace(
                first_or_none=AsyncMock(return_value=None),
                to_list=AsyncMock(return_value=[]),
            ),
        ),
        pytest.raises(UnauthorizedError) as unknown,
    ):
        await agent_services.agent_auth("token", tenant_id="tenant")
    assert unknown.value.error_code == "agent_not_found"

    inactive = MagicMock()
    inactive.is_active = False
    inactive.tenant_id = "tenant"
    inactive.uid = "agent-1"
    with (
        patch.object(db, "redis", SimpleNamespace(set=AsyncMock(return_value=True))),
        patch.object(
            agent_services,
            "UnverifiedJWT",
            return_value=SimpleNamespace(
                unverified_payload={"iss": "agent"},
                unverified_header={},
            ),
        ),
        patch.object(
            agent_services.models.Agent,
            "get_query",
            return_value=SimpleNamespace(
                first_or_none=AsyncMock(return_value=inactive),
                to_list=AsyncMock(return_value=[]),
            ),
        ),
        pytest.raises(UnauthorizedError) as disabled,
    ):
        await agent_services.agent_auth("token", tenant_id="tenant")
    assert disabled.value.error_code == "agent_not_active"


@pytest.mark.asyncio
async def test_agent_auth_wraps_unexpected_failure() -> None:
    with (
        patch.object(agent_services, "UnverifiedJWT", side_effect=RuntimeError("bad")),
        pytest.raises(UnauthorizedError) as failed,
    ):
        await agent_services.agent_auth("token", tenant_id="tenant")
    assert failed.value.error_code == "agent_auth_failed"


@pytest.mark.asyncio
async def test_refresh_rotation_rejects_invalid_store_and_replay() -> None:
    now = int(time.time())
    invalid = SimpleNamespace(jti=None, exp=now + 60, tenant_id="tenant")
    with pytest.raises(UnauthorizedError) as malformed:
        await token_services._consume_refresh_token(invalid)
    assert malformed.value.error_code == "invalid_refresh_token"

    payload = SimpleNamespace(jti="jti", exp=now + 60, tenant_id="tenant")
    with (
        patch.object(db, "redis", None),
        pytest.raises(ServiceUnavailableError) as unavailable,
    ):
        await token_services._consume_refresh_token(payload)
    assert unavailable.value.error_code == "refresh_rotation_unavailable"

    failing = SimpleNamespace(set=AsyncMock(side_effect=RuntimeError("down")))
    with (
        patch.object(db, "redis", failing),
        pytest.raises(ServiceUnavailableError),
    ):
        await token_services._consume_refresh_token(payload)

    replayed = SimpleNamespace(set=AsyncMock(return_value=False))
    with (
        patch.object(db, "redis", replayed),
        pytest.raises(UnauthorizedError) as replay,
    ):
        await token_services._consume_refresh_token(payload)
    assert replay.value.error_code == "refresh_token_reused"

    available = SimpleNamespace(set=AsyncMock(return_value=True))
    with patch.object(db, "redis", available):
        await token_services._consume_refresh_token(payload)


@pytest.mark.asyncio
async def test_session_validity_optional_missing_and_identity_mismatch() -> None:
    payload = SimpleNamespace(
        session_id="session",
        tenant_id="tenant",
        sub="user",
    )
    with patch.object(
        token_services.AuthSession,
        "find_one",
        new=AsyncMock(return_value=None),
    ):
        assert (
            await token_services.check_session_validity(
                refresh_payload=payload, raise_exception=False
            )
            is None
        )

    session = SimpleNamespace(
        is_deleted=False,
        is_expired=False,
        user_id="other",
        tenant_id="tenant",
        workspace_id=None,
    )
    with (
        patch.object(
            token_services.AuthSession,
            "find_one",
            new=AsyncMock(return_value=session),
        ),
        pytest.raises(UnauthorizedError) as mismatch,
    ):
        await token_services.check_session_validity(refresh_payload=payload)
    assert mismatch.value.error_code == "session_mismatch"
