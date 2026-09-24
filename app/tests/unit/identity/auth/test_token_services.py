"""Unit tests for token cookie helpers, session validity, and workspace roles."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone
from usso import exceptions as usso_exceptions

from apps.identity.auth.enums import LoginStatus
from apps.identity.auth.schemas import TokenType
from apps.identity.auth.services import token as token_services
from apps.identity.user.models import User
from server.exceptions import UnauthorizedError


def _request(
    *, cookies: dict | None = None, user_agent: str | None = "Mozilla/5.0"
) -> MagicMock:
    """Build a minimal request-like mock."""
    request = MagicMock()
    request.cookies = cookies or {}
    headers = {}
    if user_agent is not None:
        headers["user-agent"] = user_agent
    request.headers.get = lambda key, default=None: headers.get(key, default)
    request.url.hostname = "sso.example.test"
    return request


def _tenant_cookie(
    *, header_or_cookie: str = "cookie", domain: str = "parent"
) -> MagicMock:
    tenant = MagicMock()
    tenant.domains = ["sso.example.test", "app.example.test"]
    tenant.primary_domain = "sso.example.test"
    tenant.config.cookie_header_config.header_or_cookie = header_or_cookie
    tenant.config.cookie_header_config.cookie_domain = domain
    tenant.config.cookie_header_config.is_secure = True
    tenant.config.cookie_header_config.is_http_only = True
    tenant.config.token.get_timeout.return_value = 3600
    tenant.sign_jwt.side_effect = lambda payload, **_: "signed"
    return tenant


def test_is_cookie_auth_preferred_respects_tenant_flag() -> None:
    """Tenant without cookie auth never prefers cookies."""
    assert (
        token_services.is_cookie_auth_preferred(_request(cookies={"a": "1"}), False)
        is False
    )


def test_is_cookie_auth_preferred_with_existing_cookies() -> None:
    """Any existing cookies prefer cookie auth when tenant allows it."""
    assert (
        token_services.is_cookie_auth_preferred(
            _request(cookies={"usso-access-token": "x"}), True
        )
        is True
    )


def test_is_cookie_auth_preferred_browser_user_agent() -> None:
    """Browser UAs prefer cookies when no cookies are present yet."""
    preferred = token_services.is_cookie_auth_preferred(
        _request(cookies={}, user_agent="Chrome"), True
    )
    assert preferred is True


def test_is_cookie_auth_preferred_missing_user_agent() -> None:
    """Missing UA without cookies does not prefer cookie auth."""
    assert (
        token_services.is_cookie_auth_preferred(
            _request(cookies={}, user_agent=None), True
        )
        is False
    )


def test_remove_cookie_deletes_token_and_available() -> None:
    """remove_cookie clears both token and available cookies."""
    response = MagicMock()
    token_services.remove_cookie(
        response, TokenType.ACCESS, "sso.example.test", use_parent_domain=True
    )
    assert response.delete_cookie.call_count == 2


def test_remove_auth_cookies_iterates_token_types() -> None:
    """All token types are cleared from the response."""
    response = MagicMock()
    tenant = _tenant_cookie()
    with patch.object(token_services, "remove_cookie") as remove:
        result = token_services.remove_auth_cookies(
            response, "sso.example.test", tenant
        )
    assert result is response
    assert remove.call_count == len(list(TokenType))


def test_attach_auth_cookies_sets_tokens() -> None:
    """Access/refresh payloads are written as cookies."""
    response = MagicMock()
    tenant = _tenant_cookie()
    now = int(datetime.now(timezone.tz).timestamp())
    payloads = {
        TokenType.ACCESS: SimpleNamespace(
            token="access",
            exp=now + 60,
        ),
        TokenType.REFRESH: SimpleNamespace(
            token="refresh",
            exp=now + 120,
        ),
    }
    with patch.object(token_services, "remove_cookie") as remove:
        token_services.attach_auth_cookies_to_response(
            response=response,
            tenant=tenant,
            payloads=payloads,
            domain="sso.example.test",
        )
    remove.assert_called_once()
    assert response.set_cookie.call_count == 4


def test_render_scope_template_empty_and_invalid() -> None:
    """Empty scopes pass through; invalid templates fall back to original."""
    assert token_services._render_scope_template("", {}) == ""
    assert (
        token_services._render_scope_template("read:x?id={{ missing }}", {})
        == "read:x?id={{ missing }}"
    )


def test_expand_scope_templates_skips_empty() -> None:
    """Empty scope strings are preserved as-is."""
    user = User.model_construct(
        uid="u1",
        tenant_id="t1",
        scopes=[],
        roles=[],
        workspace_roles={},
        workspace_ids=[],
    )
    assert token_services.expand_scope_templates([""], user) == [""]


def test_expand_scope_templates_fans_out() -> None:
    """Fan-out renders each scope once per workspace id."""
    user = User.model_construct(
        uid="u1",
        tenant_id="t1",
        scopes=[],
        roles=[],
        workspace_roles={},
        workspace_ids=[],
    )
    result = token_services.expand_scope_templates(
        ["read:r?workspace_id={workspace_id}"],
        user,
        fanout_workspace_ids=["w1", "w2"],
    )
    assert "read:r?workspace_id=w1" in result
    assert "read:r?workspace_id=w2" in result


def test_collapse_equivalent_scopes_keeps_shorter() -> None:
    """Mutually equivalent scopes keep the shorter form."""
    # Force the equivalent-scope branch by mocking is_subset_scope both ways.
    with patch(
        "apps.identity.auth.services.token.authorization.is_subset_scope",
        side_effect=lambda subset_scope, super_scope: True,
    ):
        kept = token_services.collapse_overlapping_scopes(["aaaa", "bb"])
    assert kept == ["bb"]


@pytest.mark.asyncio
async def test_check_session_validity_raises_when_missing() -> None:
    """Missing/deleted sessions raise UnauthorizedError."""
    payload = SimpleNamespace(session_id="s1", tenant_id="t1", sub="u1")
    with (
        patch.object(
            token_services.AuthSession,
            "find_one",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await token_services.check_session_validity(refresh_payload=payload)
    assert exc.value.error_code == "session_not_found"


@pytest.mark.asyncio
async def test_check_session_validity_raises_when_expired() -> None:
    """Expired sessions raise UnauthorizedError."""
    payload = SimpleNamespace(session_id="s1", tenant_id="t1", sub="u1")
    session = SimpleNamespace(
        is_deleted=False,
        is_expired=True,
        workspace_id=None,
        tenant_id="t1",
        user_id="u1",
    )
    with (
        patch.object(
            token_services.AuthSession,
            "find_one",
            new=AsyncMock(return_value=session),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await token_services.check_session_validity(refresh_payload=payload)
    assert exc.value.error_code == "session_expired"


@pytest.mark.asyncio
async def test_check_session_validity_rejects_inactive_workspace() -> None:
    """Inactive workspace binding becomes UnauthorizedError."""
    from server.exceptions import ForbiddenError

    payload = SimpleNamespace(session_id="s1", tenant_id="t1", sub="u1")
    session = SimpleNamespace(
        is_deleted=False,
        is_expired=False,
        workspace_id="ws-1",
        tenant_id="t1",
        user_id="u1",
    )
    with (
        patch.object(
            token_services.AuthSession,
            "find_one",
            new=AsyncMock(return_value=session),
        ),
        patch(
            "apps.access_control.workspace.services.require_workspace_active",
            new=AsyncMock(side_effect=ForbiddenError(detail="inactive")),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await token_services.check_session_validity(refresh_payload=payload)
    assert exc.value.error_code == "workspace_not_active"


@pytest.mark.asyncio
async def test_check_session_validity_returns_session() -> None:
    """Valid sessions are returned as-is."""
    payload = SimpleNamespace(session_id="s1", tenant_id="t1", sub="u1")
    session = SimpleNamespace(
        is_deleted=False,
        is_expired=False,
        workspace_id=None,
        tenant_id="t1",
        user_id="u1",
    )
    with (
        patch.object(
            token_services.AuthSession,
            "find_one",
            new=AsyncMock(return_value=session),
        ),
        patch.object(
            token_services, "_consume_refresh_token", new=AsyncMock()
        ) as consume,
    ):
        result = await token_services.check_session_validity(refresh_payload=payload)
    assert result is session
    consume.assert_awaited_once_with(payload)


@pytest.mark.asyncio
async def test_get_workspace_roles_scopes_member_path() -> None:
    """Members resolve roles/scopes via fan-out for the workspace."""
    user = MagicMock(spec=User)
    user.workspace_ids = ["ws-1"]
    role = SimpleNamespace(name="CEO")
    user.get_roles = AsyncMock(return_value=[role])

    with patch.object(
        token_services,
        "expand_roles_with_fanout",
        new=AsyncMock(return_value=["read:x"]),
    ):
        roles, scopes = await token_services.get_workspace_roles_scopes(
            user=user, workspace_id="ws-1", user_scopes=[]
        )
    assert roles == ["CEO"]
    assert scopes == ["read:x"]


@pytest.mark.asyncio
async def test_get_workspace_roles_scopes_admin_non_member() -> None:
    """System workspace admins may enter without membership."""
    user = MagicMock(spec=User)
    user.workspace_ids = []
    user.roles = ["admin"]
    user.get_roles = AsyncMock(return_value=[])

    with (
        patch(
            "apps.access_control.workspace.services.has_system_workspace_admin",
            return_value=True,
        ),
        patch.object(
            token_services,
            "expand_roles_with_fanout",
            new=AsyncMock(return_value=["admin:sso/usso/workspace"]),
        ),
    ):
        roles, scopes = await token_services.get_workspace_roles_scopes(
            user=user,
            workspace_id="ws-1",
            user_scopes=["admin:sso/usso/workspace"],
        )
    assert roles == ["admin"]
    assert scopes == ["admin:sso/usso/workspace"]


@pytest.mark.asyncio
async def test_get_workspace_roles_scopes_denies_outsider() -> None:
    """Non-members without system admin are denied."""
    user = MagicMock(spec=User)
    user.workspace_ids = []
    with (
        patch(
            "apps.access_control.workspace.services.has_system_workspace_admin",
            return_value=False,
        ),
        pytest.raises(usso_exceptions.PermissionDenied),
    ):
        await token_services.get_workspace_roles_scopes(
            user=user, workspace_id="ws-1", user_scopes=[]
        )


def test_build_login_response_includes_tokens_without_cookies() -> None:
    """Header auth puts tokens in the JSON body."""
    tenant = _tenant_cookie(header_or_cookie="header")
    request = _request(cookies={}, user_agent="curl/8.0")
    now = int(datetime.now(timezone.tz).timestamp())
    payload = MagicMock()
    payload.token = "tok"
    payload.model_dump.return_value = {
        "sub": "u1",
        "tenant_id": "t1",
        "iss": "https://sso.example.test",
        "iat": now,
        "exp": now + 60,
        "jti": "j1",
        "token_type": TokenType.ACCESS,
        "session_id": "s1",
    }
    payloads = {TokenType.ACCESS: payload}

    with patch.object(token_services, "is_cookie_auth_preferred", return_value=False):
        response = token_services.build_login_response(
            request=request,
            tenant=tenant,
            payloads=payloads,
            status=LoginStatus.COMPLETED,
        )
    assert response.status_code == 200
    body = response.body.decode()
    assert "tok" in body or "access" in body.lower() or "tokens" in body


def test_build_login_response_attaches_cookies_when_preferred() -> None:
    """Cookie auth attaches cookies and omits tokens from body preference path."""
    tenant = _tenant_cookie()
    request = _request(cookies={"x": "1"})
    now = int(datetime.now(timezone.tz).timestamp())
    payload = MagicMock()
    payload.token = "tok"
    payload.model_dump.return_value = {
        "sub": "u1",
        "tenant_id": "t1",
        "iss": "https://sso.example.test",
        "iat": now,
        "exp": now + 60,
        "jti": "j1",
        "token_type": TokenType.ACCESS,
        "session_id": "s1",
    }
    payloads = {TokenType.ACCESS: payload}

    with (
        patch.object(token_services, "is_cookie_auth_preferred", return_value=True),
        patch.object(token_services, "attach_auth_cookies_to_response") as attach,
    ):
        token_services.build_login_response(
            request=request,
            tenant=tenant,
            payloads=payloads,
            status=LoginStatus.COMPLETED,
        )
    attach.assert_called_once()


@pytest.mark.asyncio
async def test_resolve_token_roles_scopes_uses_provided_values() -> None:
    """Explicit scopes/roles skip get_roles and use templates."""
    user = User.model_construct(
        uid="u1",
        tenant_id="t1",
        scopes=[],
        roles=[],
        workspace_roles={},
        workspace_ids=[],
    )
    roles, scopes = await token_services._resolve_token_roles_scopes(
        user=user,
        workspace_id="ws-1",
        scopes=["read:x?workspace_id={workspace_id}"],
        roles=["member"],
    )
    assert roles == ["member"]
    assert "read:x?workspace_id=ws-1" in scopes


@pytest.mark.asyncio
async def test_build_workspace_switch_response_member() -> None:
    """Workspace switch for a member creates a new session and tokens."""
    tenant = _tenant_cookie(header_or_cookie="header")
    tenant.config.workspace.enabled = True
    request = _request(cookies={}, user_agent="curl/8.0")

    user = MagicMock(spec=User)
    user.uid = "u1"
    user.tenant_id = "t1"
    user.workspace_ids = ["ws-2"]
    user.custom_claims = {}
    user.roles = []
    user.scopes = []
    user.get_roles = AsyncMock(return_value=[SimpleNamespace(name="CEO")])

    previous = MagicMock()
    previous.user_id = "u1"
    previous.workspace_id = "ws-1"
    previous.amr = ["password"]
    previous.scopes = []
    previous.meta_data = {}
    previous.claims = {}
    previous.aud = "aud"

    new_session = MagicMock()
    new_session.uid = "sess-new"
    new_session.expire_at = datetime.now(timezone.tz) + timedelta(hours=1)
    new_session.workspace_id = "ws-2"
    new_session.amr = ["password"]
    new_session.scopes = ["read:x"]
    new_session.roles = ["CEO"]
    new_session.claims = {}
    new_session.aud = "aud"
    new_session.save = AsyncMock()

    payload = MagicMock()
    payload.model_dump.side_effect = lambda include=None, **_: {
        "iss": "https://sso.example.test",
        "sub": "u1",
        "tenant_id": "t1",
        "session_id": "sess-old",
        "aud": "aud",
        "workspace_id": "ws-1",
        "roles": [],
        "scopes": [],
        "amr": [],
        "acr": None,
        "signing_level": None,
        "claims": {},
    }

    with (
        patch.object(token_services.User, "get_item", new=AsyncMock(return_value=user)),
        patch(
            "apps.access_control.workspace.services.require_workspace_active",
            new=AsyncMock(),
        ),
        patch(
            "apps.access_control.workspace.services.has_system_workspace_admin",
            return_value=False,
        ),
        patch.object(
            token_services,
            "expand_roles_with_fanout",
            new=AsyncMock(return_value=["read:x"]),
        ),
        patch.object(token_services, "AuthSession", return_value=new_session),
        patch.object(token_services, "get_location", new=AsyncMock(return_value={})),
        patch.object(token_services, "is_cookie_auth_preferred", return_value=False),
    ):
        response = await token_services.build_workspace_switch_response(
            request=request,
            tenant=tenant,
            payload=payload,
            session=previous,
            workspace_id="ws-2",
        )

    assert response.status_code == 200
    new_session.save.assert_awaited_once()
