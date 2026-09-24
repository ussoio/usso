"""Agent auth looks up by iss or kid when AGENT_ID is omitted."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey
from usso_jwt.enums import Algorithm
from usso_jwt.schemas import UnverifiedJWT

from apps.identity.agent import services
from server.exceptions import UnauthorizedError


def _query(*, first: object = None, items: list[object] | None = None) -> MagicMock:
    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=first)
    query.to_list = AsyncMock(return_value=items or [])
    return query


def _assertion(
    *,
    key: AbstractKey,
    iss: str | None = None,
    kid: str | None = None,
) -> UnverifiedJWT:
    header: dict[str, str] = {"alg": Algorithm.Ed25519.value, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    now = int(time.time())
    payload: dict[str, object] = {
        "scopes": ["read:sso/usso/*"],
        "aud": "sso",
        "exp": now + 60,
        "nbf": now - 1,
        "iat": now,
        "jti": "kid-lookup-jti-16chars",
        "tenant_id": "tenant",
    }
    if iss is not None:
        payload["iss"] = iss
    token = sign.generate_jwt(
        header=header,
        payload=payload,
        key=key.private_pem(),
        alg=Algorithm.Ed25519,
    )
    return UnverifiedJWT(token=token)


def test_kid_from_verify_key_matches_private_key() -> None:
    """Public PEM kid matches the signing key kid used by the usso client."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    assert services.kid_from_verify_key(key.public_pem().decode()) == key.kid


def test_kid_from_verify_key_rejects_garbage() -> None:
    """Invalid PEM does not raise."""
    assert services.kid_from_verify_key("not-a-key") is None


@pytest.mark.asyncio
async def test_resolve_agent_by_iss() -> None:
    """``iss`` still finds the agent by uid."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    agent = SimpleNamespace(uid="agent-1", verify_key=key.public_pem().decode())
    jwt = _assertion(key=key, iss="agent-1")
    with patch.object(
        services.models.Agent,
        "get_query",
        return_value=_query(first=agent),
    ) as get_query:
        found = await services._resolve_agent_for_auth(jwt=jwt, tenant_id="tenant")
    assert found is agent
    get_query.assert_called_once_with(uid="agent-1", tenant_id="tenant")


@pytest.mark.asyncio
async def test_resolve_agent_by_kid_without_iss() -> None:
    """Gitops IPG sends kid and omits iss when AGENT_ID is unset."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    agent = SimpleNamespace(uid="agent-1", verify_key=key.public_pem().decode())
    jwt = _assertion(key=key, kid=key.kid)
    with patch.object(
        services.models.Agent,
        "get_query",
        return_value=_query(items=[agent]),
    ) as get_query:
        found = await services._resolve_agent_for_auth(jwt=jwt, tenant_id="tenant")
    assert found is agent
    get_query.assert_called_once_with(tenant_id="tenant")


@pytest.mark.asyncio
async def test_resolve_agent_requires_iss_or_kid() -> None:
    """Missing both identifiers is invalid_token, matching the previous 401."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    jwt = _assertion(key=key)
    with pytest.raises(UnauthorizedError) as exc:
        await services._resolve_agent_for_auth(jwt=jwt, tenant_id="tenant")
    assert exc.value.error_code == "invalid_token"


@pytest.mark.asyncio
async def test_resolve_agent_kid_ambiguous() -> None:
    """Two agents with the same public key cannot be disambiguated by kid."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    pem = key.public_pem().decode()
    jwt = _assertion(key=key, kid=key.kid)
    with (
        patch.object(
            services.models.Agent,
            "get_query",
            return_value=_query(
                items=[
                    SimpleNamespace(uid="a", verify_key=pem),
                    SimpleNamespace(uid="b", verify_key=pem),
                ]
            ),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await services._resolve_agent_for_auth(jwt=jwt, tenant_id="tenant")
    assert exc.value.error_code == "agent_kid_ambiguous"


def test_unverified_iss_empty_string() -> None:
    """Blank iss is treated as missing so kid lookup can run."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    jwt = _assertion(key=key, iss="")
    assert services._unverified_iss(jwt) is None
