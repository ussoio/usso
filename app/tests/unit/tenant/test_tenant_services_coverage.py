"""Focused coverage for tenant service helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.tenant import services, startup
from server.exceptions import BadRequestError


def _tenant(*, active: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        is_active=active,
        secrets=SimpleNamespace(channel_configs={}, oauth_secrets={}),
    )


def _request(
    hostname: str | None = "tenant.test", port: int | None = None
) -> SimpleNamespace:
    return SimpleNamespace(url=SimpleNamespace(hostname=hostname, port=port))


def test_configure_oauth_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = _tenant()
    monkeypatch.delenv("USSO_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("USSO_GOOGLE_CLIENT_SECRET", raising=False)
    services._configure_oauth_from_env(tenant)
    assert tenant.secrets.oauth_secrets == {}

    monkeypatch.setenv("USSO_GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setenv("USSO_GOOGLE_CLIENT_SECRET", "google-secret")
    services._configure_oauth_from_env(tenant)
    secret = tenant.secrets.oauth_secrets["google"]
    assert secret.client_id == "google-client"
    assert secret.client_secret == "google-secret"
    assert secret.scopes == ["openid", "profile", "email"]


@pytest.mark.asyncio
async def test_get_tenant_prefers_explicit_domain() -> None:
    tenant = _tenant()
    lookup = AsyncMock(return_value=tenant)
    with patch.object(services.Tenant, "get_from_domain", new=lookup):
        assert await services.get_tenant(_request(), domain="explicit.test") is tenant
    lookup.assert_awaited_once_with("explicit.test")


@pytest.mark.asyncio
async def test_get_tenant_falls_back_from_domain_and_host_port() -> None:
    tenant = _tenant()
    lookup = AsyncMock(side_effect=[None, None, tenant])
    with patch.object(services.Tenant, "get_from_domain", new=lookup):
        result = await services.get_tenant(
            _request("tenant.test", 8443), domain="missing.test"
        )
    assert result is tenant
    assert [call.args[0] for call in lookup.await_args_list] == [
        "missing.test",
        "tenant.test:8443",
        "tenant.test",
    ]


@pytest.mark.asyncio
async def test_get_tenant_falls_back_to_first_tenant() -> None:
    tenant = _tenant()
    with (
        patch.object(
            services.Tenant, "get_from_domain", new=AsyncMock(return_value=None)
        ),
        patch.object(
            services.Tenant, "find_one", new=AsyncMock(return_value=tenant)
        ) as find_one,
    ):
        assert await services.get_tenant(_request(None)) is tenant
    find_one.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_get_tenant_raises_when_no_tenant_exists() -> None:
    with (
        patch.object(
            services.Tenant, "get_from_domain", new=AsyncMock(return_value=None)
        ),
        patch.object(services.Tenant, "find_one", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.get_tenant(_request())
    assert exc.value.error_code == "tenant_not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "json_data", "expected"),
    [
        (b"", {}, None),
        (b"{}", {}, None),
        (b'{"tenant_id":"t2"}', {"tenant_id": "t2"}, "t2"),
    ],
)
async def test_get_custom_tenant_id(
    body: bytes, json_data: dict[str, object], expected: object
) -> None:
    request = SimpleNamespace(
        body=AsyncMock(return_value=body), json=AsyncMock(return_value=json_data)
    )
    assert await services.get_custom_tenant_id(request) == expected
    if body:
        request.json.assert_awaited_once_with()
    else:
        request.json.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_request_tenant_validates_presence_and_active_status() -> None:
    with (
        patch.object(services, "get_tenant", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing,
    ):
        await services.get_request_tenant(MagicMock())
    assert missing.value.error_code == "tenant_not_found"

    inactive = _tenant(active=False)
    with (
        patch.object(services, "get_tenant", new=AsyncMock(return_value=inactive)),
        pytest.raises(BadRequestError) as disabled,
    ):
        await services.get_request_tenant(MagicMock())
    assert disabled.value.error_code == "tenant_not_active"

    active = _tenant()
    with patch.object(services, "get_tenant", new=AsyncMock(return_value=active)):
        assert await services.get_request_tenant(MagicMock()) is active


@pytest.mark.asyncio
async def test_create_first_tenant_skips_when_one_exists() -> None:
    existing = SimpleNamespace(domains=["existing.test"])
    query = SimpleNamespace(first_or_none=AsyncMock(return_value=existing))
    with (
        patch.object(startup.Tenant, "count", new=AsyncMock(return_value=1)),
        patch.object(startup.Tenant, "find", return_value=query) as find,
        patch.object(startup.logger, "info") as log,
    ):
        assert await startup.create_first_tenant() is None
    find.assert_called_once_with()
    log.assert_called_once_with(
        "%s not needed — existing tenant with domains: %s",
        startup._BOOTSTRAP_LOG_PREFIX,
        existing.domains,
    )


@pytest.mark.asyncio
async def test_create_first_tenant_skips_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SUPERADMIN_EMAIL", raising=False)
    monkeypatch.delenv("SUPERADMIN_PASSWORD", raising=False)
    with (
        patch.object(startup.Tenant, "count", new=AsyncMock(return_value=0)),
        patch.object(startup.logger, "error") as log,
    ):
        assert await startup.create_first_tenant() is None
    log.assert_called_once()
    assert "SUPERADMIN_EMAIL or SUPERADMIN_PASSWORD" in log.call_args.args[0]


@pytest.mark.asyncio
async def test_create_first_tenant_builds_and_saves_initial_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key, value in {
        "SUPERADMIN_EMAIL": "admin@example.com",
        "SUPERADMIN_PASSWORD": "SuperAdmin1!",
        "SUPERADMIN_USERNAME": "mahdikiani",
        "SUPERADMIN_NAME": "Root Admin",
        "DOMAIN": "tenant.test",
        "PROJECT_NAME": "Tenant Project",
    }.items():
        monkeypatch.setenv(key, value)

    tenant = MagicMock(name="TenantInstance")
    tenant.uid = "tenant-1"
    tenant.name = "Tenant Project"
    tenant.secrets.keys = []

    user = MagicMock(name="User")
    user.uid = "user-1"

    tenant_cls = MagicMock(return_value=tenant)
    tenant_cls.count = AsyncMock(return_value=0)

    with (
        patch.object(startup, "Tenant", tenant_cls),
        patch.object(
            startup,
            "_acquire_first_tenant_setup_lock",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            startup.TenantKey, "create_random_key", return_value=SimpleNamespace()
        ),
        patch.object(startup, "_configure_channels_from_env") as configure_channels,
        patch.object(startup, "_configure_oauth_from_env") as configure_oauth,
        patch.object(startup, "create_user", new=AsyncMock(return_value=user)),
        patch.object(startup, "_bootstrap_superadmin_identifiers", return_value=[]),
        patch.object(startup, "_persist_first_tenant", new=AsyncMock()) as persist,
        patch.object(
            startup, "_run_after_first_tenant_hooks", new=AsyncMock()
        ) as hooks,
        patch.object(startup, "_validate_bootstrap_password"),
        patch.object(startup, "_bootstrap_domains", return_value=["tenant.test"]),
        patch.object(startup.logger, "info"),
    ):
        result = await startup.create_first_tenant()

    assert result is tenant
    configure_channels.assert_called_once_with(tenant)
    configure_oauth.assert_called_once_with(tenant)
    hooks.assert_awaited_once_with(tenant)
    persist.assert_awaited_once()


def test_ensure_tenant_roles_is_exported() -> None:
    """Generic role seeding API is available for deployment overlays."""
    assert callable(startup.ensure_tenant_roles)


@pytest.mark.asyncio
async def test_create_first_tenant_skips_when_lock_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUPERADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("SUPERADMIN_PASSWORD", "SuperAdmin1!")
    with (
        patch.object(startup.Tenant, "count", new=AsyncMock(return_value=0)),
        patch.object(
            startup,
            "_acquire_first_tenant_setup_lock",
            new=AsyncMock(return_value=False),
        ),
    ):
        assert await startup.create_first_tenant() is None


@pytest.mark.asyncio
async def test_create_first_tenant_skips_password_when_weak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Weak SUPERADMIN_PASSWORD must not set the password, but still create tenant."""
    monkeypatch.setenv("SUPERADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("SUPERADMIN_PASSWORD", "NoSpecialChars123")

    tenant = MagicMock(name="TenantInstance")
    tenant.uid = "tenant-1"
    tenant.name = "USSO"
    tenant.secrets.keys = []

    user = MagicMock(name="User")
    user.uid = "user-1"

    tenant_cls = MagicMock(return_value=tenant)
    tenant_cls.count = AsyncMock(return_value=0)

    with (
        patch.object(startup, "Tenant", tenant_cls),
        patch.object(
            startup,
            "_acquire_first_tenant_setup_lock",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            startup.TenantKey, "create_random_key", return_value=SimpleNamespace()
        ),
        patch.object(startup, "_configure_channels_from_env"),
        patch.object(startup, "_configure_oauth_from_env"),
        patch.object(
            startup, "create_user", new=AsyncMock(return_value=user)
        ) as create_user,
        patch.object(startup, "_bootstrap_superadmin_identifiers", return_value=[]),
        patch.object(startup, "_persist_first_tenant", new=AsyncMock()) as persist,
        patch.object(startup, "_run_after_first_tenant_hooks", new=AsyncMock()),
        patch.object(startup, "_bootstrap_domains", return_value=["tenant.test"]),
        patch.object(startup.logger, "error") as log_error,
        patch.object(startup.logger, "info"),
    ):
        result = await startup.create_first_tenant()

    assert result is tenant
    persist.assert_awaited_once()
    create_user.assert_awaited_once()
    login = create_user.await_args.kwargs["login"]
    assert login.secret is None
    assert login.method is None
    log_error.assert_called_once()
    assert "password policy" in log_error.call_args.args[0]
    assert "without setting the password" in log_error.call_args.args[0]
    assert "Unmet:" in log_error.call_args.args[0]
