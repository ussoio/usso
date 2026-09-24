"""Unit tests for API key verification."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi_mongo_base.utils import timezone

from apps.identity.api_key import services
from apps.identity.api_key.models import APIKey
from server.exceptions import UnauthorizedError


def _db_key(**overrides: object) -> SimpleNamespace:
    key_data = services.generate_api_key()
    payload = {
        "hashed_key": key_data["hashed_key"],
        "is_active": True,
        "revoked": None,
        "expires_at": None,
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


@pytest.mark.asyncio
async def test_verify_rejects_inactive_key() -> None:
    """Reject an API key that has been disabled."""
    db_key = _db_key(is_active=False)

    with (
        mock.patch.object(APIKey, "get_query") as get_query,
        mock.patch.object(
            services.PasswordHasherService,
            "verify_password",
            return_value=True,
        ),
    ):
        get_query.return_value.to_list = mock.AsyncMock(return_value=[db_key])
        with pytest.raises(UnauthorizedError) as exc:
            await services.verify_api_key(services.generate_api_key()["api_key"])

    assert exc.value.error_code == "api_key_inactive"


@pytest.mark.asyncio
async def test_verify_rejects_revoked_key() -> None:
    """Reject an API key that has been revoked."""
    db_key = _db_key(revoked=object())

    with (
        mock.patch.object(APIKey, "get_query") as get_query,
        mock.patch.object(
            services.PasswordHasherService,
            "verify_password",
            return_value=True,
        ),
    ):
        get_query.return_value.to_list = mock.AsyncMock(return_value=[db_key])
        with pytest.raises(UnauthorizedError) as exc:
            await services.verify_api_key(services.generate_api_key()["api_key"])

    assert exc.value.error_code == "api_key_revoked"


@pytest.mark.asyncio
async def test_verify_rejects_expired_key() -> None:
    """Reject an API key whose expiry time has passed."""
    db_key = _db_key(
        expires_at=datetime.now(timezone.tz) - timedelta(minutes=1),
    )

    with (
        mock.patch.object(APIKey, "get_query") as get_query,
        mock.patch.object(
            services.PasswordHasherService,
            "verify_password",
            return_value=True,
        ),
    ):
        get_query.return_value.to_list = mock.AsyncMock(return_value=[db_key])
        with pytest.raises(UnauthorizedError) as exc:
            await services.verify_api_key(services.generate_api_key()["api_key"])

    assert exc.value.error_code == "api_key_expired"
