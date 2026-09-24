"""Focused route coverage for initial application setup."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.setup import routes
from apps.setup.schemas import SetupRequest
from apps.tenant.config import TenantConfig
from server.exceptions import ServiceUnavailableError, UnauthorizedError


def _setup_request(**updates: object) -> SetupRequest:
    payload = {
        "name": "Local USSO",
        "domains": ["sso.test"],
        "admin_account": {
            "name": "Admin",
            "username": "admin",
            "email": "admin@example.com",
            "password": "Strong-Password1",
            "phone": "09120000000",
        },
    }
    payload.update(updates)
    return SetupRequest.model_validate(payload)


def _request(value: str) -> MagicMock:
    request = MagicMock()
    request.headers = {"x-system-password": value}
    return request


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        secrets=SimpleNamespace(
            keys=[],
            channel_configs={},
            oauth_secrets={},
        ),
        config=TenantConfig(),
        save=AsyncMock(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("count", "status_code"), [(0, 204), (1, 409)])
async def test_setup_available_reports_tenant_state(
    count: int, status_code: int
) -> None:
    with patch.object(routes.Tenant, "count", new=AsyncMock(return_value=count)):
        response = await routes.setup_available()
    assert response.status_code == status_code


def test_configure_channels_populates_all_explicit_channels() -> None:
    tenant = _tenant()
    data = _setup_request(
        kavenegar_api="sms-key",
        email={
            "host": "smtp.test",
            "port": 587,
            "username": "mailer",
            "password": "mail-secret",
            "sender": "noreply@test",
            "use_tls": True,
        },
        oauth=[
            {
                "name": "oidc",
                "discovery_url": "https://id.test/.well-known/openid-configuration",
                "client_id": "client",
                "client_secret": "secret",
                "scopes": ["openid"],
            }
        ],
    )

    routes._configure_channels(tenant, data)

    assert set(tenant.secrets.channel_configs) == {"sms", "email"}
    assert tenant.secrets.channel_configs["sms"].provider_config == {
        "api_key": "sms-key"
    }
    assert tenant.secrets.channel_configs["email"].provider_config["use_tls"] is True
    assert tenant.secrets.oauth_secrets["oidc"].client_id == "client"


def test_configure_channels_from_env_handles_present_and_missing_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = _tenant()
    for name in ("KAVENEGAR_API_KEY",):
        monkeypatch.delenv(name, raising=False)
    routes._configure_channels_from_env(tenant)
    assert tenant.secrets.channel_configs == {}

    monkeypatch.setenv("KAVENEGAR_API_KEY", "env-sms")
    routes._configure_channels_from_env(tenant)
    assert tenant.secrets.channel_configs["sms"].provider_config == {
        "api_key": "env-sms"
    }


def test_validate_admin_password_rejects_weak_password() -> None:
    policy = SimpleNamespace(
        is_valid=False,
        unmet_requirements=["Password is too weak"],
    )
    with (
        patch(
            "apps.identity.auth.pass_validator.validate_password_policy",
            return_value=policy,
        ),
        pytest.raises(Exception, match="Password is too weak"),
    ):
        routes._validate_admin_password(_setup_request(), _tenant())


@pytest.mark.asyncio
async def test_setup_returns_conflict_when_tenant_exists() -> None:
    with (
        patch.object(routes.Settings, "system_password", "setup-secret"),
        patch.object(routes.Tenant, "count", new=AsyncMock(return_value=2)),
    ):
        response = await routes.setup(_request("setup-secret"), _setup_request())
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_setup_rejects_bad_secret_and_missing_or_contended_lock() -> None:
    with (
        patch.object(routes.Settings, "system_password", "setup-secret"),
        pytest.raises(UnauthorizedError),
    ):
        await routes.setup(_request("wrong"), _setup_request())

    with (
        patch.object(routes.Settings, "system_password", "setup-secret"),
        patch.object(routes.Tenant, "count", new=AsyncMock(return_value=0)),
        patch.object(routes, "redis", None),
        pytest.raises(ServiceUnavailableError),
    ):
        await routes.setup(_request("setup-secret"), _setup_request())

    lock = SimpleNamespace(set=AsyncMock(return_value=False))
    with (
        patch.object(routes.Settings, "system_password", "setup-secret"),
        patch.object(routes.Tenant, "count", new=AsyncMock(return_value=0)),
        patch.object(routes, "redis", lock),
    ):
        response = await routes.setup(_request("setup-secret"), _setup_request())
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_setup_rechecks_tenant_after_lock() -> None:
    lock = SimpleNamespace(set=AsyncMock(return_value=True))
    with (
        patch.object(routes.Settings, "system_password", "setup-secret"),
        patch.object(routes.Tenant, "count", new=AsyncMock(side_effect=[0, 1])),
        patch.object(routes, "redis", lock),
    ):
        response = await routes.setup(_request("setup-secret"), _setup_request())
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_setup_creates_tenant_admin_roles_and_workspace() -> None:
    tenant = _tenant()
    user = SimpleNamespace(
        uid="user-1",
        tenant_id="initial",
        roles=[],
        save=AsyncMock(),
    )
    identifiers = [SimpleNamespace(save=AsyncMock()), SimpleNamespace(save=AsyncMock())]
    roles_created = [
        SimpleNamespace(save=AsyncMock()),
        SimpleNamespace(save=AsyncMock()),
    ]
    tenant_cls = MagicMock(return_value=tenant)
    tenant_cls.count = AsyncMock(return_value=0)

    with (
        patch.object(routes.Settings, "system_password", "setup-secret"),
        patch.object(routes, "Tenant", tenant_cls),
        patch.object(routes.redis, "set", new=AsyncMock(return_value=True)),
        patch.object(routes.TenantKey, "create_random_key", return_value="key"),
        patch.object(
            routes, "create_user", new=AsyncMock(return_value=user)
        ) as create_user,
        patch.object(routes, "UserIdentifier", side_effect=identifiers),
        patch.object(routes, "Role", side_effect=roles_created),
        patch(
            "apps.access_control.workspace.services.ensure_management_workspace",
            new=AsyncMock(),
        ) as ensure_workspace,
    ):
        response = await routes.setup(_request("setup-secret"), _setup_request())

    assert response.status_code == 201
    assert tenant.secrets.keys == ["key"]
    assert tenant.user_id == "user-1"
    assert user.tenant_id == "tenant-1"
    assert user.roles == ["admin"]
    create_user.assert_awaited_once()
    tenant.save.assert_awaited_once()
    user.save.assert_awaited_once()
    assert all(role.tenant_id == "tenant-1" for role in roles_created)
    assert all(identifier.tenant_id == "tenant-1" for identifier in identifiers)
    ensure_workspace.assert_awaited_once_with(tenant=tenant, admin_user=user)
