"""test_debug_mock module."""

import pytest
from fastapi_mongo_base.core import config as fmb_config
from fastapi_mongo_base.utils import basic

from server.config import Settings


@pytest.mark.parametrize("debug", [False, True])
def test_debug_mode_mock_sync(debug: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Sync functions stay sync and return mock when debug is enabled."""

    @basic.debug_mode_mock(42)
    def add(a: int, b: int) -> int:
        return a + b

    # Decorator reads fastapi_mongo_base Settings; keep USSO Settings in sync.
    monkeypatch.setattr(fmb_config.Settings, "debug", debug)
    monkeypatch.setattr(Settings, "debug", debug)
    assert add(1, 2) == (42 if debug else 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("debug", [False, True])
async def test_debug_mode_mock_async(
    debug: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Async functions stay async and return mock when debug is enabled."""

    @basic.debug_mode_mock(99)
    async def add(a: int, b: int) -> int:  # ruff:ignore[unused-async]
        return a + b

    monkeypatch.setattr(fmb_config.Settings, "debug", debug)
    monkeypatch.setattr(Settings, "debug", debug)
    assert await add(1, 2) == (99 if debug else 3)
