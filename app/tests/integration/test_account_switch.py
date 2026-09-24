"""Browser multi-account switching and impersonation return integration tests."""

import hashlib
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi import Request, Response
from fastapi_mongo_base.utils import timezone

from apps.identity.auth.schemas import PayloadData, TokenType
from apps.identity.auth.services.account_switch import (
    ACCOUNT_SET_COOKIE,
    remember_browser_login,
)
from apps.identity.auth.services.basics import get_tenant_url
from apps.identity.session.models import AuthSession, BrowserAccountSet
from apps.identity.session.schemas import BrowserAccountEntry, SessionType
from apps.identity.user.models import User
from apps.tenant.models import Tenant


def _origin(client: httpx.AsyncClient) -> str:
    parts = urlsplit(str(client.base_url))
    return f"{parts.scheme}://{parts.netloc}"


async def _user(*, tenant: Tenant, uid: str, name: str) -> User:
    user = User(
        uid=uid,
        tenant_id=tenant.uid,
        name=name,
        is_active=True,
    )
    await user.save()
    return user


async def _session(
    *,
    tenant: Tenant,
    user: User,
    uid: str,
    session_type: SessionType = SessionType.REGULAR_LOGIN,
    claims: dict | None = None,
) -> AuthSession:
    session = AuthSession(
        uid=uid,
        tenant_id=tenant.uid,
        user_id=user.uid,
        user_agent="account-switch-test",
        ip="127.0.0.1",
        max_age_minutes=60,
        roles=[],
        scopes=[],
        amr=["password"],
        session_type=session_type,
        claims=claims,
    )
    await session.save()
    return session


async def _account_set(
    *,
    tenant: Tenant,
    raw_token: str,
    sessions: list[AuthSession],
    active: AuthSession,
) -> BrowserAccountSet:
    now = datetime.now(timezone.tz)
    account_set = BrowserAccountSet(
        tenant_id=tenant.uid,
        credential_digest=hashlib.sha256(raw_token.encode()).hexdigest(),
        entries=[
            BrowserAccountEntry(
                user_id=session.user_id,
                session_id=session.uid,
                session_type=session.session_type,
                added_at=now,
                last_used_at=now,
            )
            for session in sessions
        ],
        active_session_id=active.uid,
        expires_at=now + timedelta(hours=1),
    )
    await account_set.save()
    return account_set


async def _retire_test_records(
    *,
    users: list[User],
    sessions: list[AuthSession],
    account_set: BrowserAccountSet,
) -> None:
    """Keep this module from changing pagination totals in later tests."""
    account_set.is_deleted = True
    await account_set.save()
    for session in sessions:
        session.is_deleted = True
        await session.save()
    for user in users:
        user.is_deleted = True
        await user.save()


@pytest.mark.asyncio
async def test_lists_and_switches_between_regular_accounts(
    client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    admin = await _user(
        tenant=initial_tenant,
        uid="account-switch-admin",
        name="Admin account",
    )
    second = await _user(
        tenant=initial_tenant,
        uid="account-switch-second",
        name="Second account",
    )
    admin_session = await _session(
        tenant=initial_tenant,
        user=admin,
        uid="account-switch-admin-session",
    )
    second_session = await _session(
        tenant=initial_tenant,
        user=second,
        uid="account-switch-second-session",
    )
    raw_token = "regular-account-set-token-with-enough-entropy-0001"
    account_set = await _account_set(
        tenant=initial_tenant,
        raw_token=raw_token,
        sessions=[admin_session, second_session],
        active=admin_session,
    )
    client.cookies.set(ACCOUNT_SET_COOKIE, raw_token)

    listed = await client.get("/auth/accounts")
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "no-store"
    body = listed.json()
    assert body["active_user_id"] == admin.uid
    assert {account["user_id"] for account in body["accounts"]} == {
        admin.uid,
        second.uid,
    }

    rejected = await client.post(
        "/auth/accounts/switch",
        json={"user_id": second.uid},
        headers={"Origin": "https://attacker.example"},
    )
    assert rejected.status_code == 403

    switched = await client.post(
        "/auth/accounts/switch",
        json={"user_id": second.uid},
        headers={"Origin": _origin(client)},
    )
    assert switched.status_code == 200
    assert "usso-access-token=" in switched.headers.get("set-cookie", "")
    await account_set.sync()
    assert account_set.active_session_id == second_session.uid
    await _retire_test_records(
        users=[admin, second],
        sessions=[admin_session, second_session],
        account_set=account_set,
    )


@pytest.mark.asyncio
async def test_return_from_impersonation_restores_admin_and_revokes_target_session(
    client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    admin = await _user(
        tenant=initial_tenant,
        uid="impersonation-return-admin",
        name="Returning admin",
    )
    target = await _user(
        tenant=initial_tenant,
        uid="impersonation-return-target",
        name="Impersonated target",
    )
    admin_session = await _session(
        tenant=initial_tenant,
        user=admin,
        uid="impersonation-return-admin-session",
    )
    target_session = await _session(
        tenant=initial_tenant,
        user=target,
        uid="impersonation-return-target-session",
        session_type=SessionType.IMPERSONATION,
        claims={"impersonated_by": admin.uid},
    )
    raw_token = "impersonation-account-set-token-with-enough-entropy-0002"
    account_set = await _account_set(
        tenant=initial_tenant,
        raw_token=raw_token,
        sessions=[admin_session, target_session],
        active=target_session,
    )
    client.cookies.set(ACCOUNT_SET_COOKIE, raw_token)

    returned = await client.post(
        "/auth/impersonation/return",
        headers={"Origin": _origin(client)},
    )
    assert returned.status_code == 200
    assert "usso-access-token=" in returned.headers.get("set-cookie", "")

    await account_set.sync()
    await target_session.sync()
    assert account_set.active_session_id == admin_session.uid
    assert target_session.is_deleted is True
    assert target_session.uid not in {entry.session_id for entry in account_set.entries}
    await _retire_test_records(
        users=[admin, target],
        sessions=[admin_session, target_session],
        account_set=account_set,
    )


@pytest.mark.asyncio
async def test_impersonation_login_preserves_the_pre_login_admin_session(
    initial_tenant: Tenant,
) -> None:
    admin = await _user(
        tenant=initial_tenant,
        uid="remember-admin-before-impersonation",
        name="Remembered admin",
    )
    target = await _user(
        tenant=initial_tenant,
        uid="remember-impersonation-target",
        name="Remembered target",
    )
    admin_session = await _session(
        tenant=initial_tenant,
        user=admin,
        uid="remember-admin-session",
    )
    target_session = await _session(
        tenant=initial_tenant,
        user=target,
        uid="remember-target-session",
        session_type=SessionType.IMPERSONATION,
        claims={"impersonated_by": admin.uid},
    )
    raw_token = "remember-existing-account-set-token-with-enough-entropy-0003"
    account_set = await _account_set(
        tenant=initial_tenant,
        raw_token=raw_token,
        sessions=[admin_session],
        active=admin_session,
    )

    now = int(datetime.now(timezone.tz).timestamp())
    issuer = get_tenant_url(initial_tenant, "http://localhost:8000/")
    admin_refresh = PayloadData(
        jti=str(uuid.uuid4()),
        token_type=TokenType.REFRESH,
        iss=issuer,
        aud=issuer,
        iat=now,
        exp=now + 3600,
        sub=admin.uid,
        tenant_id=initial_tenant.uid,
        session_id=admin_session.uid,
    )
    admin_refresh.token = initial_tenant.sign_jwt(
        admin_refresh.model_dump(exclude_none=True),
        hmac=True,
    )
    target_refresh = PayloadData(
        sub=target.uid,
        tenant_id=initial_tenant.uid,
        session_id=target_session.uid,
    )
    cookie_header = (
        f"{ACCOUNT_SET_COOKIE}={raw_token}; usso-refresh-token={admin_refresh.token}"
    )
    request = Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/sso/v1/users/target/impersonate",
        "raw_path": b"/api/sso/v1/users/target/impersonate",
        "query_string": b"",
        "server": ("localhost", 8000),
        "client": ("127.0.0.1", 1234),
        "headers": [
            (b"host", b"localhost:8000"),
            (b"origin", b"http://localhost:8000"),
            (b"cookie", cookie_header.encode()),
        ],
    })
    response = Response()

    await remember_browser_login(
        request=request,
        response=response,
        tenant=initial_tenant,
        payloads={TokenType.REFRESH: target_refresh},
    )

    await account_set.sync()
    assert account_set.active_session_id == target_session.uid
    assert {entry.user_id for entry in account_set.entries} == {
        admin.uid,
        target.uid,
    }
    assert ACCOUNT_SET_COOKIE in response.headers.get("set-cookie", "")
    await _retire_test_records(
        users=[admin, target],
        sessions=[admin_session, target_session],
        account_set=account_set,
    )
