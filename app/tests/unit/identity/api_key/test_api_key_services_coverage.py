"""Focused coverage for API-key service helpers and orchestration."""

import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.identity.api_key import services
from server.exceptions import (
    ForbiddenError,
    TooManyRequestsError,
    UnauthorizedError,
)


def _key(**overrides: object) -> SimpleNamespace:
    values = {
        "uid": "key-1",
        "hashed_key": "hash",
        "hashed_client_secret": "client-hash",
        "is_active": True,
        "revoked": None,
        "expires_at": None,
        "ip_whitelist": [],
        "rate_limit": None,
        "usage_count": 0,
        "last_used_at": None,
        "tenant_id": "tenant-1",
        "workspace_id": "workspace-1",
        "scopes": ["read"],
        "user_id": "user-1",
        "created_by": "admin-1",
        "created_at": datetime(2026, 1, 2, tzinfo=timezone.tz),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _query(items: list[object]) -> MagicMock:
    query = MagicMock()
    query.to_list = AsyncMock(return_value=items)
    return query


def test_uuid_base64_round_trip() -> None:
    value = uuid.UUID("12345678-1234-5678-1234-567812345678")
    encoded = services.b64_encode_uuid_strip(value)
    assert "=" not in encoded
    assert services.b64_decode_uuid_strip(encoded) == str(value)


def test_generate_client_secret_and_api_key_shape() -> None:
    value = uuid.UUID("12345678-1234-5678-1234-567812345678")
    secret = services.generate_client_secret(length=16)
    assert isinstance(secret, str)
    assert len(secret) >= 16

    with patch.object(
        services.PasswordHasherService, "hash_password", return_value="hashed"
    ):
        generated = services.generate_api_key(value, secret_length=12)
    assert generated["uid"] == str(value)
    assert generated["api_key"].startswith("uak-")
    assert "." in generated["api_key"]
    assert generated["hashed_key"] == "hashed"
    assert generated["api_key_pattern"].startswith("uak-")
    assert generated["api_key_pattern"].endswith("*")


def test_api_key_cache_key_valid_and_malformed() -> None:
    value = uuid.UUID("12345678-1234-5678-1234-567812345678")
    bid = services.b64_encode_uuid_strip(value)
    key = services._api_key_cache_key(None, f"uak-{bid}.secret")
    wrong_secret_key = services._api_key_cache_key(None, f"uak-{bid}.wrong")
    assert key.startswith("api-key:")
    assert key != wrong_secret_key
    assert services._api_key_cache_key(None, "malformed").startswith("api-key:")


def test_ensure_aware_naive_and_aware() -> None:
    naive = datetime(2026, 1, 1)
    aware = datetime(2026, 1, 1, tzinfo=timezone.tz)
    assert services._ensure_aware(naive).tzinfo is not None
    assert services._ensure_aware(aware) is aware


def test_enforce_api_key_ip_whitelist_empty_allowed_and_denied() -> None:
    services.enforce_api_key_ip_whitelist(_key(ip_whitelist=[]), client_ip=None)
    services.enforce_api_key_ip_whitelist(
        _key(ip_whitelist=["192.0.2.1"]), client_ip="192.0.2.1"
    )
    with pytest.raises(ForbiddenError) as exc:
        services.enforce_api_key_ip_whitelist(
            _key(ip_whitelist=["192.0.2.1"]), client_ip="192.0.2.2"
        )
    assert exc.value.error_code == "api_key_ip_denied"


@pytest.mark.asyncio
async def test_enforce_rate_limit_unlimited_returns_without_redis() -> None:
    redis = SimpleNamespace(incr=AsyncMock())
    with patch.object(services, "redis", redis):
        await services.enforce_api_key_rate_limit(_key(rate_limit=None))
    redis.incr.assert_not_awaited()


@pytest.mark.asyncio
async def test_enforce_rate_limit_redis_under_and_over_limit() -> None:
    redis = SimpleNamespace(incr=AsyncMock(return_value=1), expire=AsyncMock())
    db_key = _key(rate_limit={"requests": 1, "window_seconds": 30})
    with patch.object(services, "redis", redis):
        await services.enforce_api_key_rate_limit(db_key)
    redis.expire.assert_awaited_once()

    redis.incr.return_value = 2
    with (
        patch.object(services, "redis", redis),
        pytest.raises(TooManyRequestsError) as exc,
    ):
        await services.enforce_api_key_rate_limit(db_key)
    assert exc.value.error_code == "api_key_rate_limited"


@pytest.mark.asyncio
async def test_enforce_rate_limit_redis_failure_falls_back_to_memory() -> None:
    services._rate_buckets.clear()
    redis = SimpleNamespace(
        incr=AsyncMock(side_effect=RuntimeError("redis unavailable")),
        expire=AsyncMock(),
    )
    db_key = _key(rate_limit={"max_requests": 1, "window": 60})
    with patch.object(services, "redis", redis):
        await services.enforce_api_key_rate_limit(db_key)
        with pytest.raises(TooManyRequestsError):
            await services.enforce_api_key_rate_limit(db_key)


@pytest.mark.asyncio
async def test_enforce_rate_limit_memory_window_resets() -> None:
    services._rate_buckets.clear()
    db_key = _key(rate_limit={"requests": 1, "window_seconds": 10})
    bucket = "usso:api_key_rate:key-1:10"
    services._rate_buckets[bucket] = (80, 99)
    with (
        patch.object(services, "redis", None),
        patch.object(services.time, "time", return_value=100),
    ):
        await services.enforce_api_key_rate_limit(db_key)
    assert services._rate_buckets[bucket] == (100, 1)


@pytest.mark.asyncio
async def test_record_api_key_usage_success() -> None:
    db_key = _key()
    collection = SimpleNamespace(update_one=AsyncMock())
    with patch.object(
        services.APIKey, "get_pymongo_collection", return_value=collection
    ):
        await services.record_api_key_usage(
            db_key, client_ip="192.0.2.1", user_agent="test-agent"
        )
    collection.update_one.assert_awaited_once()
    assert db_key.usage_count == 1
    assert db_key.last_ip == "192.0.2.1"
    assert db_key.last_user_agent == "test-agent"
    assert db_key.last_used_at is not None


@pytest.mark.asyncio
async def test_record_api_key_usage_swallows_database_error() -> None:
    db_key = _key()
    collection = SimpleNamespace(
        update_one=AsyncMock(side_effect=RuntimeError("database unavailable"))
    )
    with patch.object(
        services.APIKey, "get_pymongo_collection", return_value=collection
    ):
        await services.record_api_key_usage(db_key)
    assert db_key.usage_count == 0


@pytest.mark.asyncio
async def test_verify_api_key_rejects_invalid_format() -> None:
    with pytest.raises(UnauthorizedError) as exc:
        await services.verify_api_key("invalid")
    assert exc.value.error_code == "api_key_invalid"


@pytest.mark.asyncio
async def test_verify_api_key_not_found_bad_password_and_success() -> None:
    generated = services.generate_api_key()
    with (
        patch.object(services.APIKey, "get_query", return_value=_query([])),
        pytest.raises(UnauthorizedError) as missing,
    ):
        await services.verify_api_key(generated["api_key"])
    assert missing.value.error_code == "api_key_not_found"

    db_key = _key()
    with (
        patch.object(services.APIKey, "get_query", return_value=_query([db_key])),
        patch.object(
            services.PasswordHasherService, "verify_password", return_value=False
        ),
        pytest.raises(UnauthorizedError) as invalid,
    ):
        await services.verify_api_key(generated["api_key"])
    assert invalid.value.error_code == "api_key_invalid"

    with (
        patch.object(services.APIKey, "get_query", return_value=_query([db_key])),
        patch.object(
            services.PasswordHasherService, "verify_password", return_value=True
        ),
    ):
        uid, result = await services.verify_api_key(generated["api_key"])
    assert uid == generated["uid"]
    assert result is db_key


def test_api_key_to_user_data_maps_identity_fields() -> None:
    data = services.api_key_to_user_data(_key(), jti="verification-id")
    assert data.jti == "verification-id"
    assert data.sub == "key-1"
    assert data.tenant_id == "tenant-1"
    assert data.workspace_id == "workspace-1"
    assert data.amr == ["api_key"]
    assert data.user_id == "user-1"
    assert data.claims["sub_type"] == "api_key"


@pytest.mark.asyncio
async def test_get_api_key_data_happy_path() -> None:
    db_key = _key()
    ip = SimpleNamespace(get=MagicMock(return_value="192.0.2.1"))
    agent = SimpleNamespace(get=MagicMock(return_value="test-agent"))
    with (
        patch.object(
            services,
            "_verify_api_key_cached",
            new_callable=AsyncMock,
            return_value=("verification-id", "key-1"),
        ),
        patch.object(services.APIKey, "get_query", return_value=_query([db_key])),
        patch.object(services, "client_ip_var", ip),
        patch.object(services, "user_agent_var", agent),
        patch.object(services, "enforce_api_key_ip_whitelist") as whitelist,
        patch.object(
            services, "enforce_api_key_rate_limit", new_callable=AsyncMock
        ) as rate_limit,
        patch.object(services, "record_api_key_usage", new_callable=AsyncMock) as usage,
    ):
        data = await services.get_api_key_data("uak-key.secret")
    assert data.jti == "verification-id"
    whitelist.assert_called_once_with(db_key, client_ip="192.0.2.1")
    rate_limit.assert_awaited_once_with(db_key)
    usage.assert_awaited_once_with(
        db_key, client_ip="192.0.2.1", user_agent="test-agent"
    )


@pytest.mark.asyncio
async def test_get_api_key_data_rejects_deleted_cached_key() -> None:
    with (
        patch.object(
            services,
            "_verify_api_key_cached",
            new_callable=AsyncMock,
            return_value=("verification-id", "key-1"),
        ),
        patch.object(services.APIKey, "get_query", return_value=_query([])),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await services.get_api_key_data("uak-key.secret")
    assert exc.value.error_code == "api_key_not_found"


@pytest.mark.asyncio
async def test_invalidate_api_key_cache_by_uid_and_api_key() -> None:
    delete = AsyncMock()
    value = uuid.UUID("12345678-1234-5678-1234-567812345678")
    bid = services.b64_encode_uuid_strip(value)
    clear = AsyncMock()
    with (
        patch.object(services._verify_api_key_cached.cache, "delete", delete),
        patch.object(services._verify_api_key_cached.cache, "clear", clear),
    ):
        await services.invalidate_api_key_cache(uid="key-1")
        await services.invalidate_api_key_cache(api_key=f"uak-{bid}.secret")
        await services.invalidate_api_key_cache()
    clear.assert_awaited_once_with()
    delete.assert_awaited_once_with(
        services._api_key_cache_key(None, f"uak-{bid}.secret")
    )
    assert delete.await_count == 1


def test_verify_client_secret_missing_and_hasher_results() -> None:
    assert (
        services.verify_client_secret(
            db_key=_key(hashed_client_secret=None), client_secret="secret"
        )
        is False
    )
    assert services.verify_client_secret(db_key=_key(), client_secret="") is False
    with patch.object(
        services.PasswordHasherService, "verify_password", side_effect=[True, False]
    ):
        assert (
            services.verify_client_secret(db_key=_key(), client_secret="secret") is True
        )
        assert (
            services.verify_client_secret(db_key=_key(), client_secret="wrong") is False
        )


def test_validate_api_key_state_accepts_future_naive_expiry() -> None:
    services._validate_api_key_state(
        _key(expires_at=datetime.now() + timedelta(minutes=5))
    )
