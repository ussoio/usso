"""
Tenant process-startup bootstrap.

Creates the first tenant from environment variables when the database is
empty. Deployment overlays may call ensure_tenant_roles() to seed roles.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable

from usso_jwt.enums import Algorithm

from apps.access_control.role.models import Role
from apps.identity.auth import enums as auth_enums
from apps.identity.auth.schemas import LoginRequest
from apps.identity.user.models import User, UserIdentifier
from apps.identity.user.services import create_user
from apps.tenant.config import (
    AgentConfig,
    AuthenticationConfig,
    TenantConfig,
    WorkspaceConfig,
)
from apps.tenant.keys import TenantKey
from apps.tenant.messaging.schemas import TenantChannelConfig
from apps.tenant.models import Tenant
from apps.tenant.roles import RoleSpec
from apps.tenant.services import _configure_oauth_from_env
from server.config import Settings

logger = logging.getLogger(__name__)

_BOOTSTRAP_LOG_PREFIX = "[USSO bootstrap]"


def _log_bootstrap_skip(reason: str, *, details: str | None = None) -> None:
    """Log a first-tenant bootstrap skip at ERROR so it is visible in pod logs."""
    message = f"{_BOOTSTRAP_LOG_PREFIX} SKIPPED — {reason}"
    if details:
        message = f"{message} Details: {details}"
    logger.error(message)


def _log_bootstrap_success(tenant: Tenant) -> None:
    logger.info(
        "%s complete — tenant %r created for domain(s) %s",
        _BOOTSTRAP_LOG_PREFIX,
        tenant.name,
        tenant.domains,
    )


AfterFirstTenantHook = Callable[[Tenant], Awaitable[None]]
_after_first_tenant_hooks: list[AfterFirstTenantHook] = []


def register_after_first_tenant(hook: AfterFirstTenantHook) -> None:
    """Register a callback to run after the first tenant is persisted."""
    _after_first_tenant_hooks.append(hook)


async def _run_after_first_tenant_hooks(tenant: Tenant) -> None:
    """Invoke overlay hooks registered for first-tenant bootstrap."""
    for hook in _after_first_tenant_hooks:
        await hook(tenant)


async def ensure_tenant_roles(role_specs: dict[str, RoleSpec]) -> None:
    """Create or refresh tenant-wide roles for every active tenant."""
    tenants = await Tenant.find({"is_deleted": False}).to_list()
    for tenant in tenants:
        for role_name, spec in role_specs.items():
            scopes = spec["scopes"]
            description = spec["description"]
            role = await Role.find_one({
                "tenant_id": tenant.uid,
                "name": role_name,
                "workspace_id": None,
            })
            if role is None:
                await Role(
                    name=role_name,
                    description=description,
                    tenant_id=tenant.uid,
                    scopes=scopes,
                ).save()
                continue
            if (
                role.scopes != scopes
                or role.description != description
                or not role.is_active
            ):
                role.scopes = scopes
                role.description = description
                role.is_active = True
                await role.save()


def _validate_bootstrap_password(
    password: str,
    auth_config: AuthenticationConfig,
) -> None:
    """Fail startup when the environment-provided administrator password is weak."""
    from apps.identity.auth.pass_validator import validate_password_policy

    password_policy = validate_password_policy(password, auth_config)
    if not password_policy.is_valid:
        raise RuntimeError(
            "SUPERADMIN_PASSWORD does not meet the default password policy"
        )


def _configure_channels_from_env(tenant: Tenant) -> None:
    """Configure messaging channels from environment variables."""
    if os.getenv("KAVENEGAR_API_KEY"):
        tenant.secrets.channel_configs["sms"] = TenantChannelConfig(
            tenant_id=tenant.uid,
            channel_type="sms",
            provider_name="kavenegar",
            provider_config={"api_key": os.getenv("KAVENEGAR_API_KEY")},
        )

    if os.getenv("SMTP_HOST"):
        tenant.secrets.channel_configs["email"] = TenantChannelConfig(
            tenant_id=tenant.uid,
            channel_type="email",
            provider_name="smtp",
            provider_config={
                "host": os.getenv("SMTP_HOST"),
                "port": int(os.getenv("SMTP_PORT", "465")),
                "username": os.getenv("SMTP_USERNAME"),
                "password": os.getenv("SMTP_PASSWORD"),
                "sender": os.getenv("SMTP_SENDER"),
                "use_tls": os.getenv("SMTP_USE_TLS", "false").lower() == "true",
                "use_ssl": os.getenv("SMTP_USE_SSL", "true").lower() == "true",
                "verify_ssl": os.getenv("SMTP_VERIFY_SSL", "true").lower() == "true",
                "timeout": int(os.getenv("SMTP_TIMEOUT", "30")),
            },
        )


async def _acquire_first_tenant_setup_lock() -> bool:
    """Return True when this process may run first-tenant bootstrap."""
    from server import db

    if db.redis is None:
        _log_bootstrap_skip(
            "distributed setup lock is unavailable (Redis not connected).",
            details="Fix REDIS_URI or wait for Redis before USSO starts.",
        )
        return False
    acquired = await db.redis.set("usso:setup-lock", "1", nx=True, ex=300)
    if not acquired:
        logger.warning(
            "%s waiting — another setup process holds the lock.",
            _BOOTSTRAP_LOG_PREFIX,
        )
        return False
    if await Tenant.count() > 0:
        logger.info(
            "%s skipped — tenant was created by another process.",
            _BOOTSTRAP_LOG_PREFIX,
        )
        return False
    return True


def _bootstrap_domains() -> list[str]:
    domain = os.getenv("DOMAIN") or getattr(Settings, "root_url", "localhost")
    return [domain] if isinstance(domain, str) else domain


def _bootstrap_superadmin_identifiers(
    user: User,
    *,
    superadmin_username: str,
) -> list[UserIdentifier]:
    """Build optional username/phone identifiers for the bootstrap admin."""
    user_identifiers: list[UserIdentifier] = []
    if superadmin_username:
        user_identifiers.append(
            UserIdentifier(
                type=auth_enums.AuthIdentifier.USERNAME,
                identifier=superadmin_username,
                user_id=user.uid,
                tenant_id=user.tenant_id,
            )
        )
    if superadmin_phone := os.getenv("SUPERADMIN_PHONE"):
        user_identifiers.append(
            UserIdentifier(
                type=auth_enums.AuthIdentifier.PHONE,
                identifier=superadmin_phone,
                user_id=user.uid,
                tenant_id=user.tenant_id,
            )
        )
    return user_identifiers


async def _persist_first_tenant(
    tenant: Tenant,
    user: User,
    user_identifiers: list[UserIdentifier],
) -> None:
    """Save tenant, admin user, default roles, and optional identifiers."""
    roles = [
        Role(name="admin", description="Admin role", tenant_id="local", scopes=["*:*"]),
        Role(name="user", description="User role", tenant_id="local", scopes=[]),
    ]

    user.tenant_id = tenant.uid
    tenant.user_id = user.uid
    user.roles = ["admin"]
    for ui in user_identifiers:
        ui.user_id = user.uid
        ui.tenant_id = tenant.uid

    await tenant.save()
    await user.save()
    for role in roles:
        role.tenant_id = tenant.uid
        await role.save()
    for ui in user_identifiers:
        await ui.save()

    from apps.access_control.workspace.services import ensure_management_workspace

    await ensure_management_workspace(tenant=tenant, admin_user=user)


async def create_first_tenant() -> Tenant | None:
    """
    Create the first tenant from environment variables on startup.

    Only runs if no tenants exist AND SUPERADMIN_EMAIL + SUPERADMIN_PASSWORD
    are set in the environment. Username identifier comes from
    SUPERADMIN_USERNAME (do not default to ``admin``; it is a reserved name).
    Uses DOMAIN (or Settings.root_url) as the tenant domain.

    If SUPERADMIN_PASSWORD fails the password policy, the tenant and admin
    user are still created, but the password credential is not set.

    Returns:
        Created Tenant instance, or None if skipped.

    """
    tenant_count = await Tenant.count()
    if tenant_count > 0:
        tenant = await Tenant.find().first_or_none()
        logger.info(
            "%s not needed — existing tenant with domains: %s",
            _BOOTSTRAP_LOG_PREFIX,
            tenant.domains,
        )
        return None

    superadmin_email = os.getenv("SUPERADMIN_EMAIL")
    superadmin_password = os.getenv("SUPERADMIN_PASSWORD")
    superadmin_username = (os.getenv("SUPERADMIN_USERNAME") or "").strip()

    if not superadmin_email or not superadmin_password:
        _log_bootstrap_skip(
            "SUPERADMIN_EMAIL or SUPERADMIN_PASSWORD is not set.",
            details=(
                "Set both env vars or complete bootstrap via POST "
                f"{Settings.base_path}/setup on an empty database."
            ),
        )
        return None

    if not await _acquire_first_tenant_setup_lock():
        return None

    domains = _bootstrap_domains()
    logger.info(
        "%s starting — creating first tenant for domain(s) %s",
        _BOOTSTRAP_LOG_PREFIX,
        domains,
    )

    tenant_config = TenantConfig(
        auth=AuthenticationConfig(login_flow=auth_enums.PASSWORD_OR_OTP),
        agents=AgentConfig(enabled=True),
        workspace=WorkspaceConfig(enabled=True),
    )
    from apps.identity.auth.pass_validator import validate_password_policy

    password_policy = validate_password_policy(
        superadmin_password, tenant_config.auth
    )
    password_ok = password_policy.is_valid
    if not password_ok:
        # Weak env password must not block tenant creation — only skip setting it.
        unmet = "; ".join(password_policy.unmet_requirements)
        logger.error(
            "%s SUPERADMIN_PASSWORD does not meet the default password policy — "
            "creating tenant without setting the password. Details: Unmet: %s. "
            "Set a compliant password via POST %s/setup or update "
            "SUPERADMIN_PASSWORD and restart.",
            _BOOTSTRAP_LOG_PREFIX,
            unmet,
            Settings.base_path,
        )

    tenant = Tenant(
        name=os.getenv("PROJECT_NAME", "USSO"),
        domains=domains,
        user_id="init",
        config=tenant_config,
    )
    tenant.secrets.keys.append(TenantKey.create_random_key(alg=Algorithm.ES256))

    _configure_channels_from_env(tenant)
    _configure_oauth_from_env(tenant)

    user = await create_user(
        name=os.getenv("SUPERADMIN_NAME", "Admin"),
        login=LoginRequest(
            type=auth_enums.AuthIdentifier.EMAIL,
            identifier=superadmin_email,
            method=auth_enums.AuthSecret.PASSWORD if password_ok else None,
            secret=superadmin_password if password_ok else None,
        ),
        tenant=tenant,
        is_active=True,
    )

    user_identifiers = _bootstrap_superadmin_identifiers(
        user,
        superadmin_username=superadmin_username,
    )
    await _persist_first_tenant(tenant, user, user_identifiers)
    await _run_after_first_tenant_hooks(tenant)

    _log_bootstrap_success(tenant)
    return tenant
