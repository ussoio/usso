"""test_agents module."""

import logging
import time
import uuid

import httpx
import pytest
import pytest_asyncio
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey
from usso_jwt.enums import Algorithm

from apps.tenant.models import Tenant


@pytest.fixture(scope="module")
def encryption_keys() -> AbstractKey:
    """Generate Ed25519 key pair for agent tests."""
    return AbstractKey.generate_algorithm(Algorithm.Ed25519)


@pytest_asyncio.fixture(scope="module")
async def tenant() -> Tenant:
    """Get the first tenant from the database."""
    return await Tenant.find_one()


async def get_agent_id(authenticated_client: httpx.AsyncClient) -> str:
    """Get the first agent's UID from the API."""
    resp = await authenticated_client.get("/agents")
    assert resp.status_code == 200
    data: dict = resp.json()
    assert data.get("items")
    agents: list[dict] = data.get("items")
    return agents[0].get("uid")


@pytest.mark.asyncio
async def test_create_agent(authenticated_client: httpx.AsyncClient) -> None:
    """Test successful agent creation via API."""
    # Mock location service to prevent database file error
    response = await authenticated_client.post(
        "/agents",
        json={
            "name": "test-agent",
            "description": "Test agent",
            "scopes": ["read:users"],
        },
    )

    data = response.json()
    logging.info(data)
    assert response.status_code == 201
    assert data["name"] == "test-agent"
    assert data["type"] == "agent"
    assert data["private_key"]
    assert data["kid"]
    assert len(data["kid"]) == 64


@pytest.mark.asyncio
async def test_create_agent_success(
    encryption_keys: AbstractKey, authenticated_client: httpx.AsyncClient
) -> None:
    """Test successful agent creation via API."""
    # Mock location service to prevent database file error
    response = await authenticated_client.post(
        "/agents",
        json={
            "name": "test-agent",
            "description": "Test agent",
            "scopes": ["read:users"],
            "verify_key": encryption_keys.public_pem().decode(),
        },
    )

    data = response.json()
    assert response.status_code == 201
    assert data["name"] == "test-agent"
    assert data["type"] == "agent"
    assert data["kid"] == encryption_keys.kid


@pytest.mark.asyncio
async def test_agent_auth_endpoint_no_jwt(client: httpx.AsyncClient) -> None:
    """Test successful agent creation via API."""
    # Mock location service to prevent database file error
    response = await client.post("/agents/auth")

    data = response.json()
    assert response.status_code == 401
    assert data["error_code"] == "jwt_required"


@pytest.mark.asyncio
async def test_auth_agent_failed(client: httpx.AsyncClient) -> None:
    """Test successful agent creation via API."""
    # Mock location service to prevent database file error
    response = await client.post(
        "/agents/auth",
        headers={"Authorization": "Bearer test-token"},
    )

    data = response.json()
    assert response.status_code == 401
    assert data["error_code"] == "unauthorized"


@pytest.mark.asyncio
async def test_auth_agent_scope_mismatch(
    client: httpx.AsyncClient,
    authenticated_client: httpx.AsyncClient,
    encryption_keys: AbstractKey,
    tenant: Tenant,
) -> None:
    """Test successful agent creation via API."""
    agent_id = await get_agent_id(authenticated_client)
    payload = {
        "iss": agent_id,
        "scopes": ["read:users", "read:wallets"],
        "aud": "test-audience",
        "exp": int(time.time()) + 1000,
        "nbf": int(time.time()),
        "iat": int(time.time()),
        "jti": "scope-mismatch-jti",
        "tenant_id": tenant.uid,
    }

    jwt = sign.generate_jwt(
        header={"alg": Algorithm.Ed25519.value, "typ": "JWT"},
        payload=payload,
        key=encryption_keys.private_pem(),
        alg=Algorithm.Ed25519,
    )

    response = await client.post(
        "/agents/auth",
        headers={"Authorization": f"Bearer {jwt}"},
    )

    data = response.json()
    logging.info(data)

    assert response.status_code == 401
    assert data["detail"] == "JWT scope mismatch."


@pytest.mark.asyncio
async def test_auth_agent_temporal_fail(
    client: httpx.AsyncClient,
    authenticated_client: httpx.AsyncClient,
    encryption_keys: AbstractKey,
    tenant: Tenant,
) -> None:
    """Test successful agent creation via API."""
    payload = {
        "iss": await get_agent_id(authenticated_client),
        "scopes": ["read:users"],
        "aud": "test-audience",
        "exp": int(time.time()),
        "nbf": int(time.time()) - 1000,
        "iat": int(time.time()) - 1000,
        "jti": "expired-agent-jti",
        "tenant_id": tenant.uid,
    }

    jwt = sign.generate_jwt(
        header={"alg": Algorithm.Ed25519.value, "typ": "JWT"},
        payload=payload,
        key=encryption_keys.private_pem(),
        alg=Algorithm.Ed25519,
    )

    response = await client.post(
        "/agents/auth",
        headers={"Authorization": f"Bearer {jwt}"},
    )

    data = response.json()
    logging.info(data)

    assert response.status_code == 401
    assert data["detail"] == "JWT has expired"


@pytest.mark.asyncio
async def test_auth_agent_success(
    client: httpx.AsyncClient,
    authenticated_client: httpx.AsyncClient,
    encryption_keys: AbstractKey,
    tenant: Tenant,
) -> None:
    """Test successful agent creation via API."""
    payload = {
        "iss": await get_agent_id(authenticated_client),
        "scopes": ["read:users"],
        "aud": "test-audience",
        "exp": int(time.time()) + tenant.config.token.access_timeout,
        "nbf": int(time.time()),
        "iat": int(time.time()),
        "jti": "successful-agent-jti",
        "tenant_id": tenant.uid,
    }

    jwt = sign.generate_jwt(
        header={"alg": Algorithm.Ed25519.value, "typ": "JWT"},
        payload=payload,
        key=encryption_keys.private_pem(),
        alg=Algorithm.Ed25519,
    )

    response = await client.post(
        "/agents/auth",
        headers={"Authorization": f"Bearer {jwt}"},
    )

    data = response.json()
    logging.info(data)

    assert response.status_code == 200
    assert data["status"] == "completed"
    assert "access" in data["tokens"]

    replay = await client.post(
        "/agents/auth",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert replay.status_code == 401
    assert replay.json()["error_code"] == "agent_assertion_already_used"


async def _create_keyed_agent(
    authenticated_client: httpx.AsyncClient,
    key: AbstractKey,
    *,
    name: str | None = None,
) -> dict:
    """Create an agent bound to the given public key."""
    response = await authenticated_client.post(
        "/agents",
        json={
            "name": name or f"kid-agent-{uuid.uuid4().hex[:8]}",
            "description": "Kid lookup agent",
            "scopes": ["read:users"],
            "verify_key": key.public_pem().decode(),
        },
    )
    return response.json() | {"_status": response.status_code}


def _signed_agent_jwt(
    key: AbstractKey,
    tenant: Tenant,
    *,
    iss: str | None = None,
    kid: str | None = None,
) -> str:
    header: dict[str, str] = {"alg": Algorithm.Ed25519.value, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    now = int(time.time())
    payload: dict[str, object] = {
        "scopes": ["read:users"],
        "aud": "test-audience",
        "exp": now + tenant.config.token.access_timeout,
        "nbf": now,
        "iat": now,
        "jti": "test-jti-0123456789ab",
        "tenant_id": tenant.uid,
    }
    if iss is not None:
        payload["iss"] = iss
    return sign.generate_jwt(
        header=header,
        payload=payload,
        key=key.private_pem(),
        alg=Algorithm.Ed25519,
    )


@pytest.mark.asyncio
async def test_auth_agent_kid_only(
    client: httpx.AsyncClient,
    authenticated_client: httpx.AsyncClient,
    tenant: Tenant,
) -> None:
    """Agent JWT can authenticate with header kid and no iss."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    created = await _create_keyed_agent(authenticated_client, key)
    assert created["_status"] == 201
    jwt = _signed_agent_jwt(key, tenant, kid=created["kid"])

    response = await client.post(
        "/agents/auth",
        headers={"Authorization": f"Bearer {jwt}"},
    )

    data = response.json()
    assert response.status_code == 200
    assert data["status"] == "completed"
    assert data["sub"] == created["uid"]
    assert "access" in data["tokens"]


@pytest.mark.asyncio
async def test_auth_agent_iss_kid_mismatch(
    client: httpx.AsyncClient,
    authenticated_client: httpx.AsyncClient,
    tenant: Tenant,
) -> None:
    """Iss of one agent with another agent's kid is rejected."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    other = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    created = await _create_keyed_agent(authenticated_client, key)
    assert created["_status"] == 201
    jwt = _signed_agent_jwt(key, tenant, iss=created["uid"], kid=other.kid)

    response = await client.post(
        "/agents/auth",
        headers={"Authorization": f"Bearer {jwt}"},
    )

    data = response.json()
    assert response.status_code == 401
    assert data["error_code"] == "invalid_token"


@pytest.mark.asyncio
async def test_create_agent_duplicate_verify_key(
    authenticated_client: httpx.AsyncClient,
) -> None:
    """Same public key cannot be registered twice in a tenant."""
    key = AbstractKey.generate_algorithm(Algorithm.Ed25519)
    first = await _create_keyed_agent(authenticated_client, key)
    assert first["_status"] == 201
    second = await _create_keyed_agent(authenticated_client, key)

    assert second["_status"] == 409
    assert second["error_code"] == "agent_key_exists"


@pytest.mark.asyncio
async def test_update_agent(authenticated_client: httpx.AsyncClient) -> None:
    """Update agent description; scope changes stay within caller's ceiling."""
    agent_id = await get_agent_id(authenticated_client)
    payload = {
        "description": "updated-agent",
        "scopes": ["read:users"],
    }

    response = await authenticated_client.patch(f"/agents/{agent_id}", json=payload)

    data = response.json()
    logging.info(data)

    assert response.status_code == 200
    assert data.get("description") == "updated-agent"
    assert "hashed_client_secret" not in data


@pytest.mark.asyncio
async def test_delete_agent(authenticated_client: httpx.AsyncClient) -> None:
    agent_id = await get_agent_id(authenticated_client)
    response = await authenticated_client.delete(f"/agents/{agent_id}")

    data = response.json()
    logging.info(data)

    assert response.status_code == 200
