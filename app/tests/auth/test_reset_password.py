"""Tests for secure-token password change (replaces Redis reset-password)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from usso.user import TokenType

from apps.identity.auth.enums import AuthSecret
from apps.identity.auth.schemas import PayloadData
from apps.tenant.config import AuthenticationConfig, TenantConfig, TokenConfig
from server.server import app as fastapi_app

pytestmark = pytest.mark.timeout(5, func_only=True)


@pytest.fixture(scope="session")
def mongo_client() -> object:
    """Override parent mongo_client — not needed for these unit tests."""
    yield None


@pytest.fixture(scope="session")
def db(mongo_client: object) -> None:
    """Override parent db fixture — no database needed."""
    yield


@pytest.fixture(scope="session")
def initial_tenant(db: object) -> object:
    """Override parent initial_tenant — not needed."""
    yield None


@pytest_asyncio.fixture(scope="function")
async def client() -> httpx.AsyncClient:
    """AsyncClient with rate-limit overridden."""
    from apps.identity.auth import routes

    original_overrides = fastapi_app.dependency_overrides.copy()
    password_route = next(
        route for route in routes.router_limited.routes if route.path == "/password"
    )
    rate_limiter = password_route.dependant.dependencies[0].call

    async def _noop_rate_limiter() -> None:  # ruff:ignore[unused-async]
        return None

    fastapi_app.dependency_overrides[rate_limiter] = _noop_rate_limiter
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url="http://test.usso.io/api/sso/v1",
    ) as ac:
        yield ac

    fastapi_app.dependency_overrides = original_overrides


def _make_tenant() -> MagicMock:
    tenant = MagicMock()
    tenant.uid = "tenant-001"
    tenant.primary_url = "https://test.usso.io"
    tenant.primary_domain = "test.usso.io"
    tenant.domains = ["test.usso.io"]
    tenant.config = TenantConfig(
        auth=AuthenticationConfig(),
        token=TokenConfig(secure_session_timeout=300),
    )
    tenant.config.cookie_header_config.header_or_cookie = "header"
    return tenant


@pytest.mark.asyncio
async def test_old_reset_password_endpoints_gone(client: httpx.AsyncClient) -> None:
    """Legacy Redis reset-password routes are removed."""
    resp = await client.post(
        "/auth/reset-password",
        json={"identifier": "a@b.com", "type": "email"},
    )
    assert resp.status_code == 404

    resp = await client.post(
        "/auth/reset-password/verify",
        json={"token": "x", "new_password": "Abcdef1!"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_set_password_requires_secure_token(client: httpx.AsyncClient) -> None:
    """POST /auth/password without secure token returns 401."""
    with patch(
        "apps.identity.auth.routes.get_request_tenant",
        new_callable=AsyncMock,
        return_value=_make_tenant(),
    ):
        resp = await client.post(
            "/auth/password",
            json={"new_password": "Abcdefg1!"},
        )
    assert resp.status_code == 401
    assert resp.json().get("error_code") == "secure_token_required"


@pytest.mark.asyncio
async def test_set_password_with_secure_token_updates_credential(
    client: httpx.AsyncClient,
) -> None:
    """Valid secure token allows password set/update."""
    tenant = _make_tenant()
    secure = PayloadData(
        jti="j1",
        token_type=TokenType.SECURE_TOKEN,
        sub="user-1",
        tenant_id=tenant.uid,
        amr=[AuthSecret.PHONE_OTP.value],
    )

    user = MagicMock()
    user.uid = "user-1"
    user.tenant_id = tenant.uid

    cred = MagicMock()
    cred.save = AsyncMock()
    find_mock = MagicMock()
    find_mock.to_list = AsyncMock(return_value=[cred])

    with (
        patch(
            "apps.identity.auth.routes.get_request_tenant",
            new_callable=AsyncMock,
            return_value=tenant,
        ),
        patch(
            "apps.identity.auth.routes.require_secure_token",
            return_value=secure,
        ),
        patch(
            "apps.identity.user.models.User.get_item",
            new_callable=AsyncMock,
            return_value=user,
        ),
        patch(
            "apps.identity.user.models.Credential.get_query",
            return_value=find_mock,
        ),
        patch(
            "utils.hasher.PasswordHasherService.hash_password",
            return_value="hashed",
        ),
        patch(
            "apps.identity.auth.pass_validator.validate_password_policy",
            return_value=MagicMock(is_valid=True, unmet_requirements=[]),
        ),
        patch(
            "apps.identity.session.models.AuthSession.revoke_user_sessions",
            new_callable=AsyncMock,
        ) as revoke_sessions,
    ):
        resp = await client.post(
            "/auth/password",
            json={"new_password": "Abcdefg1!"},
        )

    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    assert cred.secret == "hashed"
    cred.save.assert_awaited_once()
    revoke_sessions.assert_awaited_once_with(
        tenant_id=tenant.uid,
        user_id="user-1",
    )
