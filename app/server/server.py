"""
FastAPI application server setup and configuration.

This module creates and configures the main FastAPI application instance,
including all routers, middleware, and lifecycle management.
"""

from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi_mongo_base.core import app_factory

from apps.access_control.role.routes import router as role_router
from apps.access_control.workspace.routes import router as workspace_router
from apps.captcha.routes import router as captcha_router
from apps.identity.agent.routes import router as agent_router
from apps.identity.api_key.routes import router as api_key_router
from apps.identity.auth.routes import router as auth_router
from apps.identity.kyc.routes import router as kyc_router
from apps.identity.legal.routes import router as legal_router
from apps.identity.profile.routes import router as profile_router
from apps.identity.referral.routes import router as referral_router
from apps.identity.session.routes import router as session_router
from apps.identity.user.routes import router as user_router
from apps.setup.routes import router as setup_router
from apps.tenant.integration import integration_router, oauth_router
from apps.tenant.routes import router as tenant_router
from apps.tenant.scope_catalog.bootstrap import register_usso_scope_catalog
from apps.tenant.scope_catalog.routes import router as scope_catalog_router
from apps.tenant.startup import create_first_tenant
from server.middlewares import RequestContextMiddleware
from server.rate_limiter import init_rate_limiter

from . import config

_init_functions: list = [
    init_rate_limiter,
    create_first_tenant,
    register_usso_scope_catalog,
]

app = app_factory.create_app(
    settings=config.Settings(),
    init_functions=_init_functions,
    origins=["http://localhost:3036"],
    log_route=True,
)
app.add_middleware(RequestContextMiddleware)

_extra_routers: list[tuple[APIRouter, dict]] = []


def register_extra_router(router: APIRouter, **include_kwargs: object) -> None:
    """Register an additional router (deployment overlays)."""
    _extra_routers.append((router, include_kwargs))


def register_extra_init(func: object) -> None:
    """
    Append a startup init function (deployment overlays).

    Must be called at import time before the lifespan runs. Appends to the
    same list passed into ``create_app``, so overlays run after core inits
    (including ``create_first_tenant``).
    """
    _init_functions.append(func)


def _include_extra_routers() -> None:
    for router, kwargs in _extra_routers:
        app.include_router(router, **kwargs)


server_router = APIRouter()

for router in [
    captcha_router,
    auth_router,
    profile_router,
    api_key_router,
    referral_router,
    user_router,
    kyc_router,
    legal_router,
    session_router,
    tenant_router,
    scope_catalog_router,
    role_router,
    workspace_router,
    # oidc_router,
    agent_router,
    setup_router,
]:
    server_router.include_router(router)

app.include_router(server_router, prefix=config.Settings.base_path)
app.include_router(integration_router)
app.include_router(oauth_router)
app.mount(
    f"{config.Settings.base_path}/statics",
    StaticFiles(directory="statics"),
    name="statics",
)

_include_extra_routers()
