"""Unit tests for personal workspace creation and role/scope merge."""

from types import SimpleNamespace
from unittest import mock

import pytest

from apps.access_control.workspace import services as workspace_services
from apps.identity.auth.enums import LoginStatus
from apps.identity.auth.services import token as token_services
from apps.identity.user.models import User


def _role(
    *, uid: str, name: str, scopes: list[str], workspace_id: str | None
) -> SimpleNamespace:
    return SimpleNamespace(uid=uid, name=name, scopes=scopes, workspace_id=workspace_id)


def _tenant(*, personal_active: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            workspace=SimpleNamespace(
                enabled=True,
                personal_workspace_active_by_default=personal_active,
            )
        ),
    )


@pytest.mark.asyncio
async def test_ensure_personal_workspace_creates_workspace_and_owner_role() -> None:
    """New users get a personal workspace with uid == user.uid and owner role."""
    user = SimpleNamespace(
        uid="user-abc",
        tenant_id="tenant-1",
        name="Ada",
        workspace_ids=[],
        workspace_roles={},
        save=mock.AsyncMock(),
    )
    workspace = SimpleNamespace(uid="user-abc", tenant_id="tenant-1")
    workspace.save = mock.AsyncMock(return_value=workspace)
    owner_role = SimpleNamespace(name="owner")
    created_kwargs: dict[str, object] = {}

    class _WorkspaceStub:
        find_one = mock.AsyncMock(return_value=None)

        def __new__(cls, **kwargs: object) -> SimpleNamespace:
            created_kwargs.update(kwargs)
            return workspace

    with (
        mock.patch(
            "apps.access_control.workspace.services.Workspace",
            _WorkspaceStub,
        ),
        mock.patch.object(
            workspace_services,
            "_init_personal_workspace_roles",
            new=mock.AsyncMock(return_value=owner_role),
        ),
    ):
        result = await workspace_services.ensure_personal_workspace(
            user=user, tenant=_tenant()
        )

    assert result is workspace
    assert created_kwargs["uid"] == "user-abc"
    assert created_kwargs["tenant_id"] == "tenant-1"
    assert created_kwargs["name"] == "شخصی"
    assert created_kwargs["slug"] == "personal-user-abc"
    assert created_kwargs["is_active"] is False
    assert created_kwargs["meta_data"] == {"kind": "personal"}
    assert "user-abc" in user.workspace_ids
    assert user.workspace_roles["user-abc"] == ["owner"]
    user.save.assert_awaited()
    workspace.save.assert_awaited()


@pytest.mark.asyncio
async def test_ensure_personal_workspace_is_idempotent() -> None:
    """Existing personal membership and owner role are not duplicated."""
    user = SimpleNamespace(
        uid="user-abc",
        tenant_id="tenant-1",
        name="Ada",
        workspace_ids=["user-abc"],
        workspace_roles={"user-abc": ["owner"]},
        save=mock.AsyncMock(),
    )
    existing = SimpleNamespace(uid="user-abc", tenant_id="tenant-1", is_active=False)
    existing.save = mock.AsyncMock()
    owner_role = SimpleNamespace(name="owner")

    with (
        mock.patch.object(
            workspace_services.Workspace,
            "find_one",
            new=mock.AsyncMock(return_value=existing),
        ),
        mock.patch.object(
            workspace_services,
            "_init_personal_workspace_roles",
            new=mock.AsyncMock(return_value=owner_role),
        ),
    ):
        result = await workspace_services.ensure_personal_workspace(
            user=user, tenant=_tenant()
        )

    assert result is existing
    assert existing.is_active is False
    existing.save.assert_not_awaited()
    user.save.assert_not_awaited()
    assert user.workspace_ids == ["user-abc"]
    assert user.workspace_roles == {"user-abc": ["owner"]}


@pytest.mark.asyncio
async def test_ensure_personal_workspace_activates_when_config_default_true() -> None:
    """Existing inactive personal workspaces sync when tenant default is active."""
    user = SimpleNamespace(
        uid="user-abc",
        tenant_id="tenant-1",
        name="Ada",
        workspace_ids=["user-abc"],
        workspace_roles={"user-abc": ["owner"]},
        save=mock.AsyncMock(),
    )
    existing = SimpleNamespace(uid="user-abc", tenant_id="tenant-1", is_active=False)
    existing.save = mock.AsyncMock()
    owner_role = SimpleNamespace(name="owner")

    with (
        mock.patch.object(
            workspace_services.Workspace,
            "find_one",
            new=mock.AsyncMock(return_value=existing),
        ),
        mock.patch.object(
            workspace_services,
            "_init_personal_workspace_roles",
            new=mock.AsyncMock(return_value=owner_role),
        ),
    ):
        result = await workspace_services.ensure_personal_workspace(
            user=user, tenant=_tenant(personal_active=True)
        )

    assert result is existing
    assert existing.is_active is True
    existing.save.assert_awaited_once()
    user.save.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_roles_none_is_tenant_only() -> None:
    """Without an active workspace, only tenant-wide roles are returned."""
    user = User.model_construct(
        uid="user-abc",
        tenant_id="tenant-1",
        roles=["member"],
        workspace_roles={"user-abc": ["owner"]},
        workspace_ids=["user-abc"],
        scopes=["direct:scope"],
    )
    tenant_role = _role(
        uid="r1", name="member", scopes=["tenant:read"], workspace_id=None
    )

    def fake_get_query(**kwargs: object) -> mock.Mock:
        query = mock.Mock()
        assert kwargs.get("workspace_id") is None
        query.to_list = mock.AsyncMock(return_value=[tenant_role])
        return query

    with mock.patch(
        "apps.identity.user.models.Role.get_query",
        side_effect=fake_get_query,
    ):
        roles = await user.get_roles(None)

    assert {r.name for r in roles} == {"member"}


@pytest.mark.asyncio
async def test_get_roles_personal_keeps_tenant_and_adds_owner() -> None:
    """Personal workspace JWT context merges tenant roles with owner."""
    user = User.model_construct(
        uid="user-abc",
        tenant_id="tenant-1",
        roles=["member"],
        workspace_roles={"user-abc": ["owner"]},
        workspace_ids=["user-abc"],
        scopes=["direct:scope"],
    )
    tenant_role = _role(
        uid="r1", name="member", scopes=["tenant:read"], workspace_id=None
    )
    personal_role = _role(
        uid="r2",
        name="owner",
        scopes=["read:sso/*/*?workspace_id={workspace_id}"],
        workspace_id="user-abc",
    )

    calls: list[dict] = []

    def fake_get_query(**kwargs: object) -> mock.Mock:
        calls.append(kwargs)
        query = mock.Mock()
        if kwargs.get("workspace_id") is None:
            query.to_list = mock.AsyncMock(return_value=[tenant_role])
        else:
            query.to_list = mock.AsyncMock(return_value=[personal_role])
        return query

    with (
        mock.patch(
            "apps.identity.user.models.Role.get_query",
            side_effect=fake_get_query,
        ),
        mock.patch(
            "apps.access_control.workspace.services.list_membered_active_descendant_ids",
            new=mock.AsyncMock(return_value=[]),
        ),
    ):
        roles = await user.get_roles("user-abc")

    assert {r.name for r in roles} == {"member", "owner"}
    assert any(c.get("workspace_id") is None for c in calls)
    assert any(c.get("workspace_id") == "user-abc" for c in calls)


@pytest.mark.asyncio
async def test_get_roles_org_keeps_tenant_and_adds_org() -> None:
    """Org workspace context keeps tenant roles and adds org workspace roles."""
    user = User.model_construct(
        uid="user-abc",
        tenant_id="tenant-1",
        roles=["member"],
        workspace_roles={
            "user-abc": ["owner"],
            "org-ws": ["CEO"],
        },
        workspace_ids=["user-abc", "org-ws"],
        scopes=["direct:scope"],
    )
    tenant_role = _role(
        uid="r1", name="member", scopes=["tenant:read"], workspace_id=None
    )
    org_role = _role(
        uid="r3",
        name="CEO",
        scopes=["read:sso/*/*?workspace_id={workspace_id}"],
        workspace_id="org-ws",
    )

    def fake_get_query(**kwargs: object) -> mock.Mock:
        query = mock.Mock()
        if kwargs.get("workspace_id") is None:
            query.to_list = mock.AsyncMock(return_value=[tenant_role])
        elif kwargs.get("workspace_id") == "org-ws":
            query.to_list = mock.AsyncMock(return_value=[org_role])
        else:
            query.to_list = mock.AsyncMock(return_value=[])
        return query

    with (
        mock.patch(
            "apps.identity.user.models.Role.get_query",
            side_effect=fake_get_query,
        ),
        mock.patch(
            "apps.access_control.workspace.services.list_membered_active_descendant_ids",
            new=mock.AsyncMock(return_value=[]),
        ),
    ):
        roles = await user.get_roles("org-ws")

    assert {r.name for r in roles} == {"member", "CEO"}
    assert all(r.name != "owner" for r in roles)


@pytest.mark.asyncio
async def test_get_scopes_merges_user_scopes_and_roles() -> None:
    """get_scopes unions direct user scopes with all resolved role scopes."""
    user = User.model_construct(
        uid="user-abc",
        tenant_id="tenant-1",
        roles=["member"],
        workspace_roles={"org-ws": ["CEO"]},
        scopes=["user:direct"],
    )
    roles = [
        _role(uid="r1", name="member", scopes=["tenant:read"], workspace_id=None),
        _role(
            uid="r3",
            name="CEO",
            scopes=["ws:read?workspace_id={workspace_id}"],
            workspace_id="org-ws",
        ),
    ]

    with mock.patch.object(User, "get_roles", new=mock.AsyncMock(return_value=roles)):
        scopes = await user.get_scopes("org-ws")

    assert set(scopes) == {
        "user:direct",
        "tenant:read",
        "ws:read?workspace_id={workspace_id}",
    }


@pytest.mark.asyncio
async def test_create_token_response_defaults_to_personal_workspace() -> None:
    """When personal workspace is active, completed login puts its uid in JWT."""
    user = SimpleNamespace(
        uid="user-abc",
        tenant_id="tenant-1",
        custom_claims={},
        get_roles=mock.AsyncMock(return_value=[]),
        get_scopes=mock.AsyncMock(return_value=["s1"]),
    )
    tenant = SimpleNamespace(
        config=SimpleNamespace(
            workspace=SimpleNamespace(enabled=True),
            token=SimpleNamespace(
                get_timeout=mock.Mock(return_value=60),
                refresh_timeout=2_592_000,
            ),
            cookie_header_config=SimpleNamespace(),
        ),
        primary_url="https://example.test",
        sign_jwt=mock.Mock(return_value="signed"),
    )
    login_flow_result = SimpleNamespace(
        status=LoginStatus.COMPLETED,
        amr=[],
    )
    session = SimpleNamespace(uid="sess-1", save=mock.AsyncMock())
    personal = SimpleNamespace(uid="user-abc", is_active=True)

    with (
        mock.patch(
            "apps.access_control.workspace.services.ensure_personal_workspace",
            new=mock.AsyncMock(return_value=personal),
        ) as ensure_ws,
        mock.patch(
            "apps.access_control.workspace.services.require_workspace_active",
            new=mock.AsyncMock(return_value=personal),
        ),
        mock.patch.object(
            token_services,
            "AuthSession",
            return_value=session,
        ) as session_cls,
        mock.patch.object(
            token_services,
            "get_location",
            new=mock.AsyncMock(return_value={}),
        ),
        mock.patch.object(
            token_services,
            "get_tenant_url",
            return_value="https://example.test",
        ),
        mock.patch.object(
            token_services,
            "expand_roles_with_fanout",
            new=mock.AsyncMock(return_value=["s1"]),
        ),
    ):
        payloads = await token_services.create_token_response(
            user=user,
            tenant=tenant,
            login_flow_result=login_flow_result,
            aud="aud",
        )

    ensure_ws.assert_awaited_once_with(user=user, tenant=tenant)
    assert session_cls.call_args.kwargs["workspace_id"] == "user-abc"
    access = payloads[token_services.TokenType.ACCESS]
    assert access.workspace_id == "user-abc"


@pytest.mark.asyncio
async def test_create_token_response_skips_workspace_when_disabled() -> None:
    """When workspace is disabled, JWT workspace_id stays unset."""
    user = SimpleNamespace(
        uid="user-abc",
        tenant_id="tenant-1",
        custom_claims={},
        get_roles=mock.AsyncMock(return_value=[]),
        get_scopes=mock.AsyncMock(return_value=["s1"]),
    )
    tenant = SimpleNamespace(
        config=SimpleNamespace(
            workspace=SimpleNamespace(enabled=False),
            token=SimpleNamespace(
                get_timeout=mock.Mock(return_value=60),
                refresh_timeout=2_592_000,
            ),
        ),
        primary_url="https://example.test",
        sign_jwt=mock.Mock(return_value="signed"),
    )
    login_flow_result = SimpleNamespace(
        status=LoginStatus.COMPLETED,
        amr=[],
    )
    session = SimpleNamespace(uid="sess-1", save=mock.AsyncMock())

    with (
        mock.patch(
            "apps.access_control.workspace.services.ensure_personal_workspace",
            new=mock.AsyncMock(),
        ) as ensure_ws,
        mock.patch.object(
            token_services,
            "AuthSession",
            return_value=session,
        ) as session_cls,
        mock.patch.object(
            token_services,
            "get_location",
            new=mock.AsyncMock(return_value={}),
        ),
        mock.patch.object(
            token_services,
            "get_tenant_url",
            return_value="https://example.test",
        ),
        mock.patch.object(
            token_services,
            "expand_roles_with_fanout",
            new=mock.AsyncMock(return_value=["s1"]),
        ),
    ):
        payloads = await token_services.create_token_response(
            user=user,
            tenant=tenant,
            login_flow_result=login_flow_result,
            aud="aud",
        )

    ensure_ws.assert_not_awaited()
    assert session_cls.call_args.kwargs["workspace_id"] is None
    access = payloads[token_services.TokenType.ACCESS]
    assert access.workspace_id is None
