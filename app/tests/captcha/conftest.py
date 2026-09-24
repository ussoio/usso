"""
Conftest for captcha-specific tests.

These tests mock all external dependencies (Redis, MongoDB) and only need
the FastAPI ASGI transport — no real database initialization required.

The parent conftest has autouse=True session-scoped fixtures (db, initial_tenant)
that fail due to mongomock_motor incompatibility. We override them here as no-ops.
"""

from collections.abc import AsyncGenerator

import httpx
import pytest
import pytest_asyncio

from server.server import app as fastapi_app


@pytest.fixture(scope="session")
def mongo_client() -> object:
    """Override parent mongo_client — not needed for captcha tests."""
    yield None


@pytest.fixture(scope="session")
def db(mongo_client: object) -> None:
    """Override parent db fixture — no database needed for captcha tests."""
    yield


@pytest.fixture(scope="session")
def initial_tenant(db: object) -> object:
    """Override parent initial_tenant — not needed for captcha tests."""
    yield None


@pytest_asyncio.fixture(scope="function")
async def client() -> AsyncGenerator[httpx.AsyncClient]:
    """Fixture to provide an AsyncClient for FastAPI app without DB init."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app),
        base_url="http://test.usso.io/api/sso/v1/",
    ) as ac:
        yield ac
