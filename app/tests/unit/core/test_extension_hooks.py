"""Coverage for pure-core extension hooks and tenant startup helpers."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import APIRouter

from apps.access_control.workspace import scopes
from apps.access_control.workspace.verification import registry
from apps.access_control.workspace.verification.base import AbstractWorkspaceVerifier
from apps.identity.kyc import services as kyc_services
from apps.identity.kyc.provider import (
    NoopKycProvider,
    get_kyc_provider,
    set_kyc_provider,
)
from apps.tenant import startup
from apps.tenant.roles import RoleSpec
from server import server as server_module
from server.exceptions import BadRequestError


@pytest.mark.asyncio
async def test_noop_kyc_provider_succeeds() -> None:
    provider = NoopKycProvider()
    assert await provider.verify_phone("001", "0912") is True
    assert await provider.verify_civil("001", "1370/01/01") == {}
    assert await provider.init_kyc("001", "0912") == {}
    assert await provider.verify_kyc("kyc-1") is True


def test_set_kyc_provider_swaps_active_backend() -> None:
    original = get_kyc_provider()

    class Stub:
        async def verify_phone(self, national_code: str, phone: str) -> bool:
            return False

        async def verify_civil(
            self, national_code: str, birth_date_shamsi: str
        ) -> dict:
            return {"ok": True}

        async def init_kyc(self, national_code: str, phone: str) -> dict:
            return {"id": "1"}

        async def verify_kyc(self, kyc_id: str) -> bool:
            return False

    set_kyc_provider(Stub())
    try:
        assert get_kyc_provider() is not original
    finally:
        set_kyc_provider(original)


@pytest.mark.asyncio
async def test_kyc_services_delegate_to_provider() -> None:
    class Stub:
        async def verify_phone(self, national_code: str, phone: str) -> bool:
            assert phone == "09121234567"
            return True

        async def verify_civil(
            self, national_code: str, birth_date_shamsi: str
        ) -> dict:
            return {"nationalId": national_code}

        async def init_kyc(self, national_code: str, phone: str) -> dict:
            return {"session": "s1"}

        async def verify_kyc(self, kyc_id: str) -> bool:
            return kyc_id == "ok"

    original = get_kyc_provider()
    set_kyc_provider(Stub())
    try:
        assert await kyc_services.verify_phone("001", "989121234567") is True
        assert await kyc_services.verify_civil("001", "1370/01/01") == {
            "nationalId": "001"
        }
        assert await kyc_services.init_kyc("001", "0912") == {"session": "s1"}
        assert await kyc_services.verify_kyc("ok") is True
    finally:
        set_kyc_provider(original)


def test_register_default_workspace_scopes_overrides_lists() -> None:
    before = scopes.get_default_workspace_scopes()
    member_scope = "read:sso/usso/workspace?workspace_id={workspace_id}"
    scopes.register_default_workspace_scopes({
        "workspace_member_scopes": [member_scope]
    })
    after = scopes.get_default_workspace_scopes()
    assert after["workspace_member_scopes"] == [member_scope]
    scopes.register_default_workspace_scopes(before)


@pytest.mark.asyncio
async def test_ensure_tenant_roles_creates_and_updates() -> None:
    specs: dict[str, RoleSpec] = {
        "ops": {"description": "Ops", "scopes": ["manage:usso/workspace"]},
    }
    existing = SimpleNamespace(
        scopes=["old"],
        description="old",
        is_active=False,
        save=AsyncMock(),
    )
    created = SimpleNamespace(save=AsyncMock())
    role_cls = MagicMock(return_value=created)
    role_cls.find_one = AsyncMock(side_effect=[None, existing])
    tenant = SimpleNamespace(uid="t1")
    with (
        patch(
            "apps.tenant.startup.Tenant.find",
            return_value=SimpleNamespace(
                to_list=AsyncMock(return_value=[tenant, tenant])
            ),
        ),
        patch("apps.tenant.startup.Role", role_cls),
    ):
        await startup.ensure_tenant_roles(specs)
    assert created.save.await_count == 1
    assert existing.save.await_count == 1
    assert existing.scopes == ["manage:usso/workspace"]
    assert existing.is_active is True


def test_register_extra_router_is_included() -> None:
    router = APIRouter()
    server_module._extra_routers.clear()
    with patch.object(server_module.app, "include_router") as include:
        server_module.register_extra_router(router, prefix="/overlay")
        server_module._include_extra_routers()
    include.assert_called_once_with(router, prefix="/overlay")
    server_module._extra_routers.clear()


def test_register_extra_init_appends_to_shared_list() -> None:
    before = list(server_module._init_functions)

    async def _overlay_init() -> None:
        await asyncio.sleep(0)

    try:
        server_module.register_extra_init(_overlay_init)
        assert server_module._init_functions[-1] is _overlay_init
    finally:
        server_module._init_functions[:] = before


@pytest.mark.asyncio
async def test_register_after_first_tenant_runs_hooks() -> None:
    seen: list[object] = []

    async def _hook(tenant: object) -> None:
        await asyncio.sleep(0)
        seen.append(tenant)

    before = list(startup._after_first_tenant_hooks)
    try:
        startup._after_first_tenant_hooks.clear()
        startup.register_after_first_tenant(_hook)
        await startup._run_after_first_tenant_hooks("tenant")
        assert seen == ["tenant"]
    finally:
        startup._after_first_tenant_hooks[:] = before


def test_verification_registry_register_get_and_clear() -> None:
    registry.clear_registry()

    class Dummy(AbstractWorkspaceVerifier):
        name = "dummy"

        async def verify_create(self, **kwargs: object) -> None:
            return None

    registered = registry.register(Dummy())
    assert registered.name == "dummy"
    assert "dummy" in registry.registered_names()
    assert registry.get_verifier("dummy") is registered
    with pytest.raises(BadRequestError):
        registry.get_verifier("missing")
    with pytest.raises(ValueError):
        empty = Dummy()
        empty.name = ""
        registry.register(empty)
    registry.clear_registry()
    assert registry.registered_names() == frozenset()


def test_configure_channels_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = SimpleNamespace(uid="t1", secrets=SimpleNamespace(channel_configs={}))
    monkeypatch.setenv("KAVENEGAR_API_KEY", "sms-key")
    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "u")
    monkeypatch.setenv("SMTP_PASSWORD", "p")
    monkeypatch.setenv("SMTP_SENDER", "s@test")
    monkeypatch.setenv("SMTP_USE_TLS", "true")
    monkeypatch.setenv("SMTP_USE_SSL", "false")
    monkeypatch.setenv("SMTP_VERIFY_SSL", "false")
    monkeypatch.setenv("SMTP_TIMEOUT", "10")
    startup._configure_channels_from_env(tenant)
    assert "sms" in tenant.secrets.channel_configs
    assert "email" in tenant.secrets.channel_configs
    assert tenant.secrets.channel_configs["email"].provider_config["port"] == 587


@pytest.mark.asyncio
async def test_acquire_first_tenant_setup_lock_paths() -> None:
    with patch("server.db.redis", None), patch.object(startup.logger, "error") as log:
        assert await startup._acquire_first_tenant_setup_lock() is False
    assert "Redis not connected" in log.call_args.args[0]

    redis = AsyncMock()
    redis.set = AsyncMock(return_value=False)
    with patch("server.db.redis", redis), patch.object(startup.logger, "warning"):
        assert await startup._acquire_first_tenant_setup_lock() is False

    redis.set = AsyncMock(return_value=True)
    with (
        patch("server.db.redis", redis),
        patch.object(startup.Tenant, "count", new=AsyncMock(return_value=1)),
        patch.object(startup.logger, "info"),
    ):
        assert await startup._acquire_first_tenant_setup_lock() is False

    with (
        patch("server.db.redis", redis),
        patch.object(startup.Tenant, "count", new=AsyncMock(return_value=0)),
    ):
        assert await startup._acquire_first_tenant_setup_lock() is True


def test_bootstrap_domains_and_identifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMAIN", "example.test")
    assert startup._bootstrap_domains() == ["example.test"]
    monkeypatch.delenv("DOMAIN", raising=False)
    with patch.object(startup.Settings, "root_url", "from-settings.test"):
        assert startup._bootstrap_domains() == ["from-settings.test"]

    user = SimpleNamespace(uid="u1", tenant_id="t1")
    monkeypatch.setenv("SUPERADMIN_PHONE", "+989121111111")
    with patch("apps.tenant.startup.UserIdentifier", side_effect=lambda **kw: kw):
        identifiers = startup._bootstrap_superadmin_identifiers(
            user, superadmin_username="root"
        )
    assert len(identifiers) == 2


@pytest.mark.asyncio
async def test_persist_first_tenant_saves_graph() -> None:
    tenant = MagicMock()
    tenant.uid = "t1"
    tenant.user_id = "init"
    tenant.save = AsyncMock()
    user = MagicMock()
    user.uid = "u1"
    user.tenant_id = "old"
    user.roles = []
    user.save = AsyncMock()
    identifier = MagicMock()
    identifier.user_id = "x"
    identifier.tenant_id = "y"
    identifier.save = AsyncMock()
    role = MagicMock()
    role.tenant_id = "z"
    role.save = AsyncMock()

    with (
        patch("apps.tenant.startup.Role", side_effect=[role, role]),
        patch(
            "apps.access_control.workspace.services.ensure_management_workspace",
            new=AsyncMock(),
        ) as ensure,
    ):
        await startup._persist_first_tenant(tenant, user, [identifier])

    assert tenant.user_id == "u1"
    assert user.tenant_id == "t1"
    assert user.roles == ["admin"]
    tenant.save.assert_awaited()
    user.save.assert_awaited()
    identifier.save.assert_awaited()
    ensure.assert_awaited_once()


def test_validate_bootstrap_password_rejects_weak() -> None:
    auth = MagicMock()
    with (
        patch(
            "apps.identity.auth.pass_validator.validate_password_policy",
            return_value=SimpleNamespace(is_valid=False),
        ),
        pytest.raises(RuntimeError),
    ):
        startup._validate_bootstrap_password("weak", auth)


@pytest.mark.asyncio
async def test_get_user_national_code_paths() -> None:
    from apps.access_control.workspace import services as workspace_services
    from apps.identity.auth.enums import AuthIdentifier

    with patch.object(
        workspace_services.User, "get_item", new=AsyncMock(return_value=None)
    ):
        assert (
            await workspace_services.get_user_national_code(user_id="u", tenant_id="t")
            is None
        )

    user = MagicMock()
    user.get_identifiers = AsyncMock(
        return_value=[
            SimpleNamespace(type=AuthIdentifier.PHONE, identifier="0912"),
            SimpleNamespace(type=AuthIdentifier.NATIONAL_ID, identifier="001"),
        ]
    )
    with patch.object(
        workspace_services.User, "get_item", new=AsyncMock(return_value=user)
    ):
        assert (
            await workspace_services.get_user_national_code(user_id="u", tenant_id="t")
            == "001"
        )

    user.get_identifiers = AsyncMock(return_value=[])
    with patch.object(
        workspace_services.User, "get_item", new=AsyncMock(return_value=user)
    ):
        assert (
            await workspace_services.get_user_national_code(user_id="u", tenant_id="t")
            is None
        )


@pytest.mark.asyncio
async def test_auth_session_revoke_user_sessions() -> None:
    from apps.identity.session.models import AuthSession

    collection = MagicMock()
    collection.update_many = AsyncMock(return_value=SimpleNamespace(modified_count=2))
    with patch.object(AuthSession, "get_pymongo_collection", return_value=collection):
        assert await AuthSession.revoke_user_sessions(tenant_id="t", user_id="u") == 2


def test_role_get_queryset_workspace_filters() -> None:
    from apps.access_control.role.models import Role

    with patch(
        "fastapi_mongo_base.models.BaseEntity.get_queryset",
        return_value={"tenant_id": "t1"},
    ):
        assert Role.get_queryset()["workspace_id"] is None
        assert Role.get_queryset(workspace_id="w1")["$or"] == [{"workspace_id": "w1"}]
        qs = Role.get_queryset(workspace_id_in=["a", "b"])
        assert qs["$or"] == [{"workspace_id": "a"}, {"workspace_id": "b"}]


def test_config_required_secret_helper_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from server import config as server_config

    monkeypatch.delenv("SYSTEM_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        server_config._required_secret("SYSTEM_PASSWORD")
