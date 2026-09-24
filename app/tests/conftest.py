"""conftest module."""

import logging
import os
import sys
from collections.abc import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from beanie import init_beanie
from fastapi_mongo_base import models
from fastapi_mongo_base.utils import basic
from testcontainers.community.redis import RedisContainer

# Settings fields are read at import time — set test defaults before app imports.
for _key, _value in (
    ("PROJECT_NAME", "usso"),
    ("SYSTEM_PASSWORD", "test-system-password-at-least-32-bytes"),
    ("CAPTCHA_KEY", "test-captcha-key-at-least-32-bytes-long"),
    ("SUPERADMIN_EMAIL", "admin@test.usso.io"),
    ("SUPERADMIN_PASSWORD", "TestPassword123!"),
    ("SUPERADMIN_NAME", "Test Admin"),
):
    if not os.getenv(_key):
        os.environ[_key] = _value

TEST_ADMIN_EMAIL = os.environ["SUPERADMIN_EMAIL"]
TEST_ADMIN_PASSWORD = os.environ["SUPERADMIN_PASSWORD"]


def _use_redis_container() -> bool:
    """Use a Redis testcontainer for integration; mock Redis for unit tests."""
    mode = os.getenv("USSO_TEST_REDIS", "auto").lower()
    if mode in {"real", "container"}:
        return True
    if mode in {"mock", "unit"}:
        return False
    paths = [
        arg
        for arg in sys.argv[1:]
        if not arg.startswith("-")
        and ("test" in arg or "/" in arg or arg.endswith(".py"))
    ]
    if not paths:
        return True
    return not all("unit" in path.replace("\\", "/") for path in paths)


# App initializes Redis at import time — provide a live or mocked client first.
_redis_container = None
_redis_init_patcher = None
if _use_redis_container():
    _redis_container = RedisContainer("redis:7.4-alpine")
    _redis_container.start()
    os.environ["REDIS_URI"] = (
        f"redis://{_redis_container.get_container_host_ip()}:"
        f"{_redis_container.get_exposed_port(6379)}/0"
    )
else:
    import fastapi_mongo_base.db as fmb_db

    _redis_init_patcher = patch.object(
        fmb_db,
        "init_redis",
        return_value=(MagicMock(name="redis_sync"), AsyncMock(name="redis_async")),
    )
    _redis_init_patcher.start()

from apps.tenant.models import Tenant  # ruff:ignore[module-import-not-at-top-of-file]
from server.config import Settings  # ruff:ignore[module-import-not-at-top-of-file]
from server.server import (  # ruff:ignore[module-import-not-at-top-of-file]
    app as fastapi_app,
)

_MESSAGING_ENV_KEYS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_SENDER",
    "SMTP_USE_TLS",
    "SMTP_USE_SSL",
    "SMTP_VERIFY_SSL",
    "KAVENEGAR_API_KEY",
    "RESEND_API_KEY",
    "USSO_BALE_CLIENT_ID",
    "USSO_BALE_CLIENT_SECRET",
    "TEST_EMAIL",
    "TEST_PHONE",
)


def _running_messaging_integration_tests() -> bool:
    return any(
        "/messaging/" in arg.replace("\\", "/")
        for arg in sys.argv[1:]
        if not arg.startswith("-")
    )


if not _running_messaging_integration_tests():
    for _key in _MESSAGING_ENV_KEYS:
        os.environ.pop(_key, None)


@pytest.fixture(scope="session", autouse=True)
def setup_debugpy() -> None:
    """Set up debugpy if DEBUGPY environment variable is set."""
    if os.getenv("DEBUGPY", "False").lower() in ("true", "1", "yes"):
        import debugpy  # ruff:ignore[debugger]

        debugpy.listen(("127.0.0.1", 3020))  # ruff:ignore[debugger]
        logging.info("Waiting for debugpy client")
        debugpy.wait_for_client()  # ruff:ignore[debugger]


@pytest.fixture(scope="session", autouse=True)
def init_log() -> None:
    """Initialize the logger."""
    Settings.config_logger()


def pytest_unconfigure() -> None:
    """Stop the Redis container or mock started before application imports."""
    if _redis_container is not None:
        _redis_container.stop()
    if _redis_init_patcher is not None:
        _redis_init_patcher.stop()


@pytest_asyncio.fixture(scope="session")
async def mongo_client() -> AsyncGenerator[object]:
    """Provide an isolated, real MongoDB instance for integration tests."""
    from pymongo import AsyncMongoClient
    from testcontainers.community.mongodb import MongoDbContainer

    with MongoDbContainer("mongo:7.0") as mongo:
        client = AsyncMongoClient(mongo.get_connection_url())
        await client.server_info()
        yield client
        await client.close()


async def init_db(mongo_client: object) -> None:
    """Async setup function to initialize the database with Beanie."""
    database = mongo_client.get_database("test_db")
    await init_beanie(
        database=database,
        document_models=basic.get_all_subclasses(models.BaseEntity),
    )


def _root_domain() -> str:
    """Hostname used for tenant lookup (Settings.root_url may include a scheme)."""
    root = Settings.root_url.rstrip("/")
    return root.removeprefix("https://").removeprefix("http://")


def _tenant_domains() -> list[str]:
    """Domains that must resolve for local test HTTP clients and JWT issuers."""
    root = Settings.root_url.rstrip("/")
    host = _root_domain()
    return list(
        dict.fromkeys([
            root,
            host,
            "localhost:8000",
            "localhost",
            "dev.usso.io",
            "test.usso.io",
            "127.0.0.1",
        ])
    )


@pytest_asyncio.fixture(scope="session", autouse=True)
async def initial_tenant(db: None) -> Tenant:
    """Create initial tenant for tests."""
    from apps.tenant import startup as tenant_startup
    from apps.tenant.messaging.schemas import TenantChannelConfig

    create_first = getattr(tenant_startup, "create_first_tenant", None)
    fallback_domains = _tenant_domains()
    tenant: Tenant | None = None
    if create_first:
        tenant = await create_first()
    if tenant is None:
        tenant = await Tenant.find_one()
    if tenant is None:
        logging.info("create_first not exists.")
        tenant = Tenant(
            name="Test Tenant",
            domains=fallback_domains,
            uid="test-tenant",
            user_id="system",
        )
        await tenant.save()

    merged_domains = list(dict.fromkeys([*tenant.domains, *fallback_domains]))
    changed = merged_domains != tenant.domains
    if changed:
        tenant.domains = merged_domains
    if any("localhost" in domain for domain in tenant.domains) and (
        tenant.config.cookie_header_config.is_secure
    ):
        tenant.config.cookie_header_config.is_secure = False
        changed = True

    # Dummy messaging channels so OTP/resend endpoints work without real providers.
    channel_configs = tenant.secrets.channel_configs
    if "sms" not in channel_configs:
        channel_configs["sms"] = TenantChannelConfig(
            tenant_id=tenant.uid,
            channel_type="sms",
            provider_name="kavenegar",
            provider_config={"api_key": "test-kavenegar-key"},
            is_active=True,
        )
        changed = True
    if "email" not in channel_configs:
        channel_configs["email"] = TenantChannelConfig(
            tenant_id=tenant.uid,
            channel_type="email",
            provider_name="smtp",
            provider_config={
                "host": "localhost",
                "port": 1025,
                "username": "test",
                "password": "test",
                "sender": "noreply@test.usso.io",
                "use_tls": False,
                "use_ssl": False,
                "verify_ssl": False,
            },
            is_active=True,
        )
        changed = True

    if changed:
        await tenant.save()
    return tenant


@pytest.fixture(autouse=True)
def mute_outbound_messaging(request: pytest.FixtureRequest) -> Generator[None]:
    """Prevent real SMS/email sends, except in messaging unit/integration tests."""
    if "/messaging/" in str(request.path).replace("\\", "/"):
        yield
        return
    with patch(
        "apps.tenant.messaging.services.asend",
        new_callable=AsyncMock,
    ):
        yield


@pytest_asyncio.fixture(autouse=True, scope="function")
async def clear_redis_cache() -> AsyncGenerator[None]:
    """Flush Redis between tests so aiocache does not leak state."""
    from server.db import redis

    if redis is not None:
        await redis.flushall()

    yield


@pytest_asyncio.fixture(scope="session", autouse=True)
async def db(mongo_client: object) -> None:
    """Initialize the database."""
    logging.info("Initializing database")
    await init_db(mongo_client)
    logging.info("Database initialized")
    yield
    logging.info("Cleaning up database")


@pytest.fixture(scope="session", autouse=True)
def disable_rate_limiter_for_tests() -> Generator[None]:
    """Disable rate limiting for all tests."""
    from fastapi import Request, Response

    from server.rate_limiter import PathRateLimiter

    async def _noop_rate_limiter(  # ruff:ignore[unused-async]
        _self: PathRateLimiter, _request: Request, _response: Response
    ) -> None:
        return None

    with patch.object(PathRateLimiter, "__call__", _noop_rate_limiter):
        yield


def _api_base_url() -> str:
    """Build API base URL aligned with tenant JWT issuers."""
    root = Settings.root_url.rstrip("/")
    if root.startswith(("http://", "https://")):
        return f"{root}{Settings.base_path}"
    if root == "localhost" or root.startswith(("localhost:", "127.0.0.1")):
        return f"http://{root}{Settings.base_path}"
    return f"https://{root}{Settings.base_path}"


@pytest_asyncio.fixture(scope="session")
async def client() -> AsyncGenerator[httpx.AsyncClient]:
    """Fixture to provide an AsyncClient for FastAPI app."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url=_api_base_url(),
    ) as ac:
        yield ac


@pytest.fixture(scope="session")
def sync_client() -> AsyncGenerator[httpx.Client]:
    """Fixture to provide an AsyncClient for FastAPI app."""
    from fastapi.testclient import TestClient

    with TestClient(fastapi_app, base_url=_api_base_url()) as tc:
        yield tc


async def solve_captcha_challenge(client: httpx.AsyncClient) -> str:
    """Solve the captcha challenge."""
    import base64
    import json

    from apps.captcha.schemas import ChallengeResponse

    resp = await client.get("/captcha/challenge")
    challenge = ChallengeResponse(**resp.json())
    for num in range(challenge.max_number):
        if challenge.check_secret(num):
            break
    altcha_payload = base64.b64encode(
        json.dumps(challenge.model_dump() | {"number": num}).encode()
    ).decode()
    response = await client.post("/captcha/verify", json={"payload": altcha_payload})
    logging.info(f"{response.status_code} {response.text}")
    return altcha_payload


@pytest_asyncio.fixture(scope="session")
async def captcha_client(client: httpx.AsyncClient) -> httpx.AsyncClient:
    """Fixture to provide an AsyncClient with captcha challenge solved."""
    altcha_payload = await solve_captcha_challenge(client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url=client.base_url,
        headers={"x-altcha-payload": altcha_payload},
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def authenticated_client(
    captcha_client: httpx.AsyncClient,
) -> AsyncGenerator[httpx.AsyncClient]:
    """Provide an authenticated client with fresh tokens for each test."""
    from types import SimpleNamespace

    from usso_jwt.schemas import UnverifiedJWT

    from apps.identity.auth.enums import AuthSecret
    from apps.identity.auth.services.secure_token import create_secure_token_payload

    captcha_client.cookies.clear()
    with patch(
        "apps.captcha.schemas.ValidationRequest.validate_usage",
        new=AsyncMock(return_value=True),
    ):
        response = await captcha_client.post(
            "/auth/login",
            json={
                "type": "email",
                "identifier": TEST_ADMIN_EMAIL,
                "method": "password",
                "secret": TEST_ADMIN_PASSWORD,
            },
        )
    response.raise_for_status()
    body = response.json()
    access_token = body["tokens"]["access"]
    refresh_token = body["tokens"].get("refresh")
    payload = UnverifiedJWT(token=access_token).unverified_payload

    tenant = await Tenant.get_by_uid(payload["tenant_id"])
    assert tenant is not None
    secure = create_secure_token_payload(
        user=SimpleNamespace(uid=payload["sub"], tenant_id=payload["tenant_id"]),
        tenant=tenant,
        amr=[AuthSecret.PHONE_OTP.value],
        iss=payload.get("iss"),
    )

    cookies = dict(captcha_client.cookies)
    if refresh_token:
        cookies["usso-refresh-token"] = refresh_token
        cookies["usso-refresh-available"] = "true"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url=captcha_client.base_url,
        cookies=cookies,
        headers={
            **captcha_client.headers,
            "authorization": f"bearer {access_token}",
            "x-usso-secure-token": secure.token,
        },
    ) as ac:
        yield ac
