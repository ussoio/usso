"""Unit test conftest — override session DB fixtures."""

from collections.abc import Generator

import pytest


@pytest.fixture(scope="session")
def mongo_client() -> Generator[None]:
    """Skip Mongo client for unit tests."""
    yield None


@pytest.fixture(scope="session")
def db() -> Generator[None]:
    """Skip parent session database initialization for unit tests."""
    yield


@pytest.fixture(scope="session", autouse=True)
def initial_tenant() -> Generator[None]:
    """Skip tenant bootstrap for unit tests."""
    yield


@pytest.fixture(autouse=True, scope="function")
def clear_redis_cache() -> Generator[None]:
    """Skip Redis flush for unit tests."""
    yield
