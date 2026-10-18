"""Setup routes."""

import os
import secrets

from fastapi import APIRouter, Depends, Request, Response, status
from usso_jwt.enums import Algorithm

from apps.access_control.role.models import Role
from apps.identity.auth import enums as auth_enums
from apps.identity.auth.schemas import LoginRequest
from apps.identity.user.models import UserIdentifier
from apps.identity.user.services import (
    bootstrap_audit_scope,
    create_user,
    record_user_created,
)
from apps.tenant.config import (
    AgentConfig,
    AuthenticationConfig,
    TenantConfig,
    WorkspaceConfig,
)
from apps.tenant.keys import TenantKey
from apps.tenant.messaging.schemas import TenantChannelConfig
from apps.tenant.models import Tenant
from apps.tenant.secrets import OAuthSecret
from server.config import Settings
from server.db import redis
from server.exceptions import (
    BadRequestError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from server.rate_limiter import get_rate_limiter

from .schemas import SetupRequest

router = APIRouter(prefix="/setup", tags=["setup"])


def _configure_channels(tenant: Tenant, setup_data: SetupRequest) -> None:
    """Configure messaging channels from setup data."""
    if setup_data.kavenegar_api:
        tenant.secrets.channel_configs["sms"] = TenantChannelConfig(
            tenant_id=tenant.uid,
            channel_type="sms",
            provider_name="kavenegar",
            provider_config={"api_key": setup_data.kavenegar_api},
        )
    if setup_data.email:
        tenant.secrets.channel_configs["email"] = TenantChannelConfig(
            tenant_id=tenant.uid,
            channel_type="email",
            provider_name="smtp",
            provider_config={
                "host": setup_data.email.host,
                "port": setup_data.email.port,
                "username": setup_data.email.username,
                "password": setup_data.email.password,
                "sender": setup_data.email.sender,
                "use_tls": setup_data.email.use_tls,
                "use_ssl": setup_data.email.use_ssl,
                "verify_ssl": setup_data.email.verify_ssl,
                "timeout": setup_data.email.timeout,
            },
        )
    if setup_data.oauth:
        for oauth in setup_data.oauth:
            tenant.secrets.oauth_secrets[oauth.name] = OAuthSecret(
                discovery_url=oauth.discovery_url,
                client_id=oauth.client_id,
                client_secret=oauth.client_secret,
                scopes=oauth.scopes,
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


def _validate_admin_password(setup_data: SetupRequest, tenant: Tenant) -> None:
    """Enforce the tenant password policy for the bootstrap administrator."""
    from apps.identity.auth.pass_validator import validate_password_policy

    password_policy = validate_password_policy(
        setup_data.admin_account.password, tenant.config.auth
    )
    if not password_policy.is_valid:
        raise BadRequestError(
            error_code="password_policy",
            detail=password_policy.unmet_requirements[0],
            message={
                "en": "Administrator password does not meet the password policy.",
                "fa": "رمز مدیر شرایط امنیتی لازم را ندارد.",
            },
        )


@router.get("/", status_code=status.HTTP_204_NO_CONTENT)
async def setup_available() -> Response:
    """
    Check if setup is available.

    Returns
    -------
    Response
        HTTP 409 Conflict if tenants already exist, HTTP 204 No Content otherwise.

    """
    tenant_count = await Tenant.count()

    if tenant_count > 0:
        return Response(status_code=status.HTTP_409_CONFLICT)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/", dependencies=[Depends(get_rate_limiter("/setup"))])
async def setup(request: Request, setup_data: SetupRequest) -> Response:
    """
    Set up the application with initial tenant data.

    Parameters
    ----------
    request : Request
        The request carrying the system setup credential.
    setup_data : SetupRequest
        The setup request containing tenant configuration.

    Returns
    -------
    Response
        HTTP response indicating setup completion.

    """
    supplied_password = request.headers.get("x-system-password", "")
    if not secrets.compare_digest(supplied_password, Settings.system_password):
        raise UnauthorizedError(
            error_code="setup_unauthorized",
            detail="Invalid setup credentials",
            message={
                "en": "Setup credentials are invalid.",
                "fa": "اطلاعات راه‌اندازی نامعتبر است.",
            },
        )

    tenant_count = await Tenant.count()

    if tenant_count > 0:
        return Response(status_code=status.HTTP_409_CONFLICT)

    if redis is None:
        raise ServiceUnavailableError(
            error_code="setup_lock_unavailable",
            detail="Setup lock is unavailable",
        )
    acquired = await redis.set("usso:setup-lock", "1", nx=True, ex=300)
    if not acquired:
        return Response(status_code=status.HTTP_409_CONFLICT)
    # Close the check/use race after acquiring the distributed lock.
    if await Tenant.count() > 0:
        return Response(status_code=status.HTTP_409_CONFLICT)

    tenant = Tenant(
        name=setup_data.name,
        domains=setup_data.domains,
        user_id="init",
        config=TenantConfig(
            auth=AuthenticationConfig(login_flow=auth_enums.PASSWORD_OR_OTP),
            agents=AgentConfig(enabled=True),
            workspace=WorkspaceConfig(enabled=True),
        ),
    )
    tenant.secrets.keys.append(TenantKey.create_random_key(alg=Algorithm.ES256))
    _configure_channels(tenant, setup_data)
    _validate_admin_password(setup_data, tenant)

    # auth=AuthenticationConfig(login_flow=auth_enums.GOOGLE_FLOW)  # ruff:ignore[commented-out-code]

    with bootstrap_audit_scope(tenant_id=tenant.uid):
        user = await create_user(
            name=setup_data.admin_account.name,
            login=LoginRequest(
                type=auth_enums.AuthIdentifier.EMAIL,
                identifier=setup_data.admin_account.email,
                method=auth_enums.AuthSecret.PASSWORD,
                secret=setup_data.admin_account.password,
            ),
            tenant=tenant,
            is_active=True,
            record_audit=False,
        )
        user_identifiers = [
            UserIdentifier(
                type=auth_enums.AuthIdentifier.USERNAME,
                identifier=setup_data.admin_account.username,
                user_id=user.uid,
                tenant_id=user.tenant_id,
            )
        ]
        if setup_data.admin_account.phone:
            user_identifiers.append(
                UserIdentifier(
                    type=auth_enums.AuthIdentifier.PHONE,
                    identifier=setup_data.admin_account.phone,
                    user_id=user.uid,
                    tenant_id=user.tenant_id,
                )
            )
        roles = [
            Role(
                name="admin",
                description="Admin role",
                tenant_id="local",
                scopes=["*:*"],
            ),
            Role(
                name="user",
                description="User role",
                tenant_id="local",
                scopes=[],
            ),
        ]
        user.tenant_id = tenant.uid
        tenant.user_id = user.uid
        user.roles = ["admin"]
        for user_identifier in user_identifiers:
            user_identifier.user_id = user.uid
            user_identifier.tenant_id = tenant.uid

        await tenant.save()
        await user.save()
        for role in roles:
            role.tenant_id = tenant.uid
            await role.save()
        for user_identifier in user_identifiers:
            await user_identifier.save()

        from apps.access_control.workspace.services import ensure_management_workspace

        await ensure_management_workspace(tenant=tenant, admin_user=user)
        await record_user_created(user)

    return Response(
        status_code=status.HTTP_201_CREATED, content="Setup completed successfully."
    )
