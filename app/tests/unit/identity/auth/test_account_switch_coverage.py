"""Branch coverage for secure browser account switching."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request, Response
from fastapi_mongo_base.utils import timezone

from apps.identity.auth.schemas import PayloadData, TokenType
from apps.identity.auth.services import account_switch
from apps.identity.session.schemas import BrowserAccountEntry, SessionType
from server.exceptions import ForbiddenError, UnauthorizedError


def _request(
    *, origin: str | None = "https://login.test", cookies: dict | None = None
) -> Request:
    headers = [(b"host", b"login.test")]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    if cookies:
        value = "; ".join(f"{key}={val}" for key, val in cookies.items())
        headers.append((b"cookie", value.encode()))
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/api/sso/v1/auth/accounts/active",
        "raw_path": b"/api/sso/v1/auth/accounts/active",
        "query_string": b"",
        "server": ("login.test", 443),
        "client": ("127.0.0.1", 1),
        "headers": headers,
    })


def test_origin_and_datetime_edge_cases() -> None:
    assert account_switch._aware_datetime(datetime(2020, 1, 1)).tzinfo is not None
    assert not account_switch.is_same_origin_request(
        _request(origin="https://login.test:invalid")
    )
    assert not account_switch.is_same_origin_request(
        _request(origin="ftp://login.test")
    )
    with pytest.raises(ForbiddenError):
        account_switch.require_same_origin_request(_request(origin=None))


@pytest.mark.asyncio
async def test_account_set_missing_expired_and_pruned() -> None:
    tenant = SimpleNamespace(uid="tenant-1")
    expired = SimpleNamespace(
        expires_at=datetime.now(timezone.tz) - timedelta(seconds=1)
    )
    with patch.object(
        account_switch.BrowserAccountSet,
        "find_one",
        new=AsyncMock(return_value=expired),
    ):
        assert (
            await account_switch._load_account_set(tenant=tenant, raw_token="x" * 40)
            is None
        )
    with (
        patch.object(
            account_switch,
            "_load_account_set",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError),
    ):
        await account_switch._require_account_set(request=_request(), tenant=tenant)

    entry = BrowserAccountEntry(user_id="user", session_id="gone")
    account_set = SimpleNamespace(
        tenant_id="tenant-1",
        entries=[entry],
        active_session_id="gone",
        save=AsyncMock(),
    )
    query = MagicMock(to_list=AsyncMock(return_value=[]))
    with patch.object(account_switch.AuthSession, "find", return_value=query):
        assert await account_switch._prune_account_set(account_set) == {}
    assert account_set.entries == []
    assert account_set.active_session_id is None
    account_set.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_previous_refresh_and_invalid_new_login_session() -> None:
    tenant = SimpleNamespace(
        uid="tenant-1",
        refresh_auth=SimpleNamespace(
            user_data_from_token=MagicMock(side_effect=ValueError("bad token"))
        ),
        config=SimpleNamespace(token=SimpleNamespace(refresh_timeout=60)),
    )
    assert (
        await account_switch._previous_refresh_session(
            request=_request(cookies={"usso-refresh-token": "bad"}), tenant=tenant
        )
        is None
    )
    await account_switch.remember_browser_login(
        request=_request(), response=Response(), tenant=tenant, payloads={}
    )

    payload = PayloadData(sub="user", tenant_id="tenant-1", session_id="new-session")
    new_account_set = SimpleNamespace(
        entries=[],
        active_session_id=None,
        expires_at=None,
        save=AsyncMock(),
    )
    with (
        patch.object(
            account_switch,
            "_load_account_set",
            new=AsyncMock(return_value=None),
        ),
        patch.object(
            account_switch,
            "_prune_account_set",
            new=AsyncMock(return_value={}),
        ),
        patch.object(
            account_switch.AuthSession, "find_one", new=AsyncMock(return_value=None)
        ),
        patch.object(
            account_switch,
            "BrowserAccountSet",
            return_value=new_account_set,
        ),
        pytest.raises(UnauthorizedError) as missing,
    ):
        await account_switch.remember_browser_login(
            request=_request(),
            response=Response(),
            tenant=tenant,
            payloads={TokenType.REFRESH: payload},
        )
    assert missing.value.error_code == "new_session_not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("active", "target", "user_id", "required", "error_code"),
    [
        (None, None, "user", True, "impersonation_not_active"),
        (
            SimpleNamespace(
                uid="imp",
                user_id="victim",
                session_type=SessionType.IMPERSONATION,
                claims={"impersonated_by": "admin"},
            ),
            None,
            "other",
            False,
            "impersonation_return_target_mismatch",
        ),
        (
            SimpleNamespace(
                uid="regular",
                user_id="admin",
                session_type=SessionType.REGULAR_LOGIN,
            ),
            None,
            "missing",
            False,
            "saved_account_session_expired",
        ),
    ],
)
async def test_switch_rejects_invalid_state(
    active: object,
    target: object,
    user_id: str,
    required: bool,
    error_code: str,
) -> None:
    entries = (
        [BrowserAccountEntry(user_id=user_id, session_id="target")]
        if target is not None
        else []
    )
    account_set = SimpleNamespace(
        active_session_id=getattr(active, "uid", None), entries=entries
    )
    sessions = {}
    if active is not None:
        sessions[active.uid] = active
    if target is not None:
        sessions["target"] = target
    with (
        patch.object(
            account_switch,
            "_require_account_set",
            new=AsyncMock(return_value=(account_set, "x" * 40)),
        ),
        patch.object(
            account_switch, "_prune_account_set", new=AsyncMock(return_value=sessions)
        ),
        pytest.raises((ForbiddenError, UnauthorizedError)) as exc,
    ):
        await account_switch._switch_to_user(
            request=_request(),
            tenant=SimpleNamespace(uid="tenant-1"),
            user_id=user_id,
            require_impersonation=required,
        )
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
async def test_switch_rejects_inactive_impersonation_and_user() -> None:
    active = SimpleNamespace(
        uid="active", user_id="admin", session_type=SessionType.REGULAR_LOGIN
    )
    old_impersonation = SimpleNamespace(
        uid="target", user_id="victim", session_type=SessionType.IMPERSONATION
    )
    account_set = SimpleNamespace(
        active_session_id="active",
        entries=[BrowserAccountEntry(user_id="victim", session_id="target")],
    )
    with (
        patch.object(
            account_switch,
            "_require_account_set",
            new=AsyncMock(return_value=(account_set, "x" * 40)),
        ),
        patch.object(
            account_switch,
            "_prune_account_set",
            new=AsyncMock(return_value={"active": active, "target": old_impersonation}),
        ),
        pytest.raises(ForbiddenError) as old,
    ):
        await account_switch.switch_browser_account(
            request=_request(), tenant=SimpleNamespace(uid="tenant-1"), user_id="victim"
        )
    assert old.value.error_code == "inactive_impersonation_cannot_resume"

    target = SimpleNamespace(
        uid="target", user_id="disabled", session_type=SessionType.REGULAR_LOGIN
    )
    account_set.entries = [BrowserAccountEntry(user_id="disabled", session_id="target")]
    with (
        patch.object(
            account_switch,
            "_require_account_set",
            new=AsyncMock(return_value=(account_set, "x" * 40)),
        ),
        patch.object(
            account_switch,
            "_prune_account_set",
            new=AsyncMock(return_value={"active": active, "target": target}),
        ),
        patch(
            "apps.identity.user.models.User.find_one",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError) as unavailable,
    ):
        await account_switch.switch_browser_account(
            request=_request(),
            tenant=SimpleNamespace(uid="tenant-1"),
            user_id="disabled",
        )
    assert unavailable.value.error_code == "saved_account_unavailable"


@pytest.mark.asyncio
async def test_return_requires_an_active_impersonation() -> None:
    account_set = SimpleNamespace(active_session_id=None)
    with (
        patch.object(
            account_switch,
            "_require_account_set",
            new=AsyncMock(return_value=(account_set, "x" * 40)),
        ),
        patch.object(
            account_switch,
            "_prune_account_set",
            new=AsyncMock(return_value={}),
        ),
        pytest.raises(ForbiddenError) as exc,
    ):
        await account_switch.return_from_impersonation(
            request=_request(), tenant=SimpleNamespace(uid="tenant-1")
        )
    assert exc.value.error_code == "impersonation_not_active"


def test_upsert_caps_browser_accounts_and_preserves_original_timestamp() -> None:
    now = datetime.now(timezone.tz)
    entries = [
        BrowserAccountEntry(
            user_id=f"user-{index}",
            session_id=f"session-{index}",
            last_used_at=now - timedelta(minutes=index),
        )
        for index in range(10)
    ]
    account_set = SimpleNamespace(entries=entries)
    session = SimpleNamespace(
        user_id="new-user",
        uid="new-session",
        session_type=SessionType.REGULAR_LOGIN,
        claims={},
    )
    account_switch._upsert_entry(account_set, session, now=now)
    assert len(account_set.entries) == 10
    assert account_set.entries[-1].user_id == "new-user"
