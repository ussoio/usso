"""Unit tests for agent kid derivation and JWT lookup."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pymongo.errors import DuplicateKeyError
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey
from usso_jwt.enums import Algorithm

from apps.identity.agent import models, services
from apps.identity.agent.schemas import AgentCreateSchema
from server import db
from server.exceptions import AlreadyExistsError, UnauthorizedError


def _redis_mock() -> SimpleNamespace:
    return SimpleNamespace(set=AsyncMock(return_value=True))


def _ed25519_key() -> AbstractKey:
    return AbstractKey.generate_algorithm(Algorithm.Ed25519)


def _agent_jwt(
    key: AbstractKey,
    *,
    iss: str | None = None,
    kid: str | None = None,
    scopes: list[str] | None = None,
    ttl: int = 120,
) -> str:
    header: dict[str, str] = {"alg": Algorithm.Ed25519.value, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    now = int(time.time())
    payload: dict[str, object] = {
        "scopes": scopes or ["read:users"],
        "aud": "test-audience",
        "exp": now + ttl,
        "nbf": now - 10,
        "iat": now,
        "jti": "test-jti-0123456789ab",
        "tenant_id": "tenant-1",
    }
    if iss is not None:
        payload["iss"] = iss
    return sign.generate_jwt(
        header=header,
        payload=payload,
        key=key.private_pem(),
        alg=Algorithm.Ed25519,
    )


def _agent(*, key: AbstractKey, kid: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        uid="agent-1",
        tenant_id="tenant-1",
        is_active=True,
        scopes=["read:users"],
        alg=Algorithm.Ed25519,
        verify_key=key.public_pem().decode(),
        kid=key.kid if kid is None else kid,
        save=AsyncMock(),
    )


def _query(*, first: object = None, items: list[object] | None = None) -> MagicMock:
    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=first)
    query.to_list = AsyncMock(return_value=items or [])
    return query


def test_kid_from_verify_key_matches_abstract_key() -> None:
    """Stored kid is SHA-256 of public SPKI DER, same as AbstractKey.kid."""
    key = _ed25519_key()
    assert services.kid_from_verify_key(key.public_pem().decode()) == key.kid


@pytest.mark.asyncio
async def test_agent_auth_by_kid() -> None:
    """Header kid is enough to resolve the agent."""
    key = _ed25519_key()
    agent = _agent(key=key)
    token = _agent_jwt(key, kid=key.kid)

    with (
        patch.object(db, "redis", _redis_mock()),
        patch.object(
            models.Agent,
            "get_query",
            return_value=_query(items=[agent]),
        ) as get_query,
        patch(
            "apps.identity.agent.services.Tenant.get_by_uid",
            new=AsyncMock(return_value=None),
        ),
    ):
        found, payload = await services.agent_auth(token, tenant_id="tenant-1")

    assert found is agent
    assert payload.iss is None
    get_query.assert_called_once_with(tenant_id="tenant-1")


@pytest.mark.asyncio
async def test_agent_auth_by_iss_still_works() -> None:
    """Iss lookup remains the default path."""
    key = _ed25519_key()
    agent = _agent(key=key)
    token = _agent_jwt(key, iss=agent.uid)

    with (
        patch.object(db, "redis", _redis_mock()),
        patch.object(
            models.Agent,
            "get_query",
            return_value=_query(first=agent),
        ) as get_query,
        patch(
            "apps.identity.agent.services.Tenant.get_by_uid",
            new=AsyncMock(return_value=None),
        ),
    ):
        found, payload = await services.agent_auth(token, tenant_id="tenant-1")

    assert found is agent
    assert payload.iss == agent.uid
    get_query.assert_called_once_with(uid=agent.uid, tenant_id="tenant-1")


@pytest.mark.asyncio
async def test_agent_auth_iss_kid_mismatch() -> None:
    """Iss and header kid must name the same agent."""
    key = _ed25519_key()
    other = _ed25519_key()
    agent = _agent(key=key)
    token = _agent_jwt(key, iss=agent.uid, kid=other.kid)

    with (
        patch.object(db, "redis", _redis_mock()),
        patch.object(
            models.Agent,
            "get_query",
            return_value=_query(first=agent),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await services.agent_auth(token, tenant_id="tenant-1")

    assert exc.value.error_code == "invalid_token"


@pytest.mark.asyncio
async def test_agent_auth_requires_iss_or_kid() -> None:
    """Neither iss nor kid is unauthorized."""
    key = _ed25519_key()
    token = _agent_jwt(key)

    with pytest.raises(UnauthorizedError) as exc:
        await services.agent_auth(token, tenant_id="tenant-1")

    assert exc.value.error_code == "invalid_token"


@pytest.mark.asyncio
async def test_agent_auth_wrong_tenant() -> None:
    """Agents from another tenant are not found."""
    key = _ed25519_key()
    agent = _agent(key=key)
    agent.tenant_id = "other-tenant"
    token = _agent_jwt(key, iss=agent.uid)

    with (
        patch.object(db, "redis", _redis_mock()),
        patch.object(
            models.Agent,
            "get_query",
            return_value=_query(first=None),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await services.agent_auth(token, tenant_id="tenant-1")

    assert exc.value.error_code == "agent_not_found"


@pytest.mark.asyncio
async def test_agent_auth_backfills_missing_kid() -> None:
    """Uid auth persists kid so later kid lookup can work."""
    key = _ed25519_key()
    agent = _agent(key=key, kid="")
    agent.kid = None
    token = _agent_jwt(key, iss=agent.uid)

    with (
        patch.object(db, "redis", _redis_mock()),
        patch.object(
            models.Agent,
            "get_query",
            return_value=_query(first=agent),
        ),
        patch.object(
            models.Agent,
            "get_by_kid",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.services.Tenant.get_by_uid",
            new=AsyncMock(return_value=None),
        ),
    ):
        found, _ = await services.agent_auth(token, tenant_id="tenant-1")

    assert found.kid == key.kid
    agent.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_agent_rejects_existing_kid_before_save() -> None:
    """Duplicate kid is rejected before insert, not only via Mongo unique index."""
    key = _ed25519_key()
    caller = SimpleNamespace(uid="user-1")
    caller_user = MagicMock()
    tenant = SimpleNamespace(uid="tenant-1")
    data = AgentCreateSchema(
        name="dup-agent",
        scopes=["read:users"],
        verify_key=key.public_pem().decode(),
        user_id="user-1",
    )
    existing = _agent(key=key)

    with (
        patch(
            "apps.identity.agent.services.resolve_create_binding",
            return_value=("user-1", None),
        ),
        patch("apps.identity.agent.services.authorize_service_account_create"),
        patch(
            "apps.identity.agent.services.resolve_scope_ceiling",
            new=AsyncMock(return_value=["read:users"]),
        ),
        patch("apps.identity.agent.services.assert_scopes_subset"),
        patch(
            "apps.identity.agent.services.generate_client_secret",
            return_value="secret",
        ),
        patch("apps.identity.agent.services.PasswordHasherService") as hasher_cls,
        patch.object(
            models.Agent,
            "get_by_kid",
            new=AsyncMock(return_value=existing),
        ) as get_by_kid,
        pytest.raises(AlreadyExistsError) as exc,
    ):
        hasher_cls.return_value.hash_password.return_value = "hashed"
        await services.generate_agent(data, tenant, caller, caller_user)

    assert exc.value.error_code == "agent_key_exists"
    get_by_kid.assert_awaited_once_with(kid=key.kid, tenant_id="tenant-1")


@pytest.mark.asyncio
async def test_generate_agent_duplicate_key_raises_already_exists() -> None:
    """Race on unique (tenant_id, kid) still maps to AlreadyExistsError."""
    key = _ed25519_key()
    caller = SimpleNamespace(uid="user-1")
    caller_user = MagicMock()
    tenant = SimpleNamespace(uid="tenant-1")
    data = AgentCreateSchema(
        name="dup-agent",
        scopes=["read:users"],
        verify_key=key.public_pem().decode(),
        user_id="user-1",
    )
    instance = MagicMock()
    instance.save = AsyncMock(side_effect=DuplicateKeyError("dup"))
    agent_cls = MagicMock(return_value=instance)
    agent_cls.get_by_kid = AsyncMock(return_value=None)

    with (
        patch(
            "apps.identity.agent.services.resolve_create_binding",
            return_value=("user-1", None),
        ),
        patch("apps.identity.agent.services.authorize_service_account_create"),
        patch(
            "apps.identity.agent.services.resolve_scope_ceiling",
            new=AsyncMock(return_value=["read:users"]),
        ),
        patch("apps.identity.agent.services.assert_scopes_subset"),
        patch(
            "apps.identity.agent.services.generate_client_secret",
            return_value="secret",
        ),
        patch("apps.identity.agent.services.PasswordHasherService") as hasher_cls,
        patch(
            "apps.identity.agent.services.models.Agent",
            agent_cls,
        ),
        pytest.raises(AlreadyExistsError) as exc,
    ):
        hasher_cls.return_value.hash_password.return_value = "hashed"
        await services.generate_agent(data, tenant, caller, caller_user)

    assert exc.value.error_code == "agent_key_exists"
    agent_cls.get_by_kid.assert_awaited_once_with(kid=key.kid, tenant_id="tenant-1")
