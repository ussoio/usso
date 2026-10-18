"""Unit tests for workspace hierarchy, fan-out, and system-admin enter."""

from types import SimpleNamespace
from unittest import mock

import pytest

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import WorkspaceSchema
from apps.identity.auth.services import token as token_services
from apps.identity.user.models import User
from server.exceptions import BadRequestError, ForbiddenError


def _user_data(
    *,
    uid: str = "u1",
    scopes: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        user_id=uid,
        uid=uid,
        tenant_id="tenant-1",
        scopes=scopes or [],
    )


def _role(
    *, uid: str, name: str, scopes: list[str], workspace_id: str | None
) -> SimpleNamespace:
    return SimpleNamespace(uid=uid, name=name, scopes=scopes, workspace_id=workspace_id)


@pytest.mark.asyncio
async def test_list_active_descendant_ids() -> None:
    """Active descendants are returned by ancestor_ids query."""
    with mock.patch.object(
        services.Workspace,
        "find",
        return_value=mock.Mock(
            to_list=mock.AsyncMock(
                return_value=[
                    SimpleNamespace(uid="c1"),
                    SimpleNamespace(uid="c2"),
                ]
            )
        ),
    ):
        result = await services.list_active_descendant_ids(
            tenant_id="tenant-1", workspace_id="p1"
        )
    assert result == ["c1", "c2"]


@pytest.mark.asyncio
async def test_create_child_rejects_personal_parent() -> None:
    """Personal workspaces cannot be parents."""
    parent = SimpleNamespace(
        uid="user-abc",
        ancestor_ids=[],
        is_personal=True,
        is_active=True,
    )
    with (
        mock.patch.object(services, "require_workspace_manage"),
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=parent),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.create_child_workspace(
            user_data=_user_data(
                scopes=["manage:sso/usso/workspace?workspace_id=user-abc"]
            ),
            item=WorkspaceSchema(
                name="Child",
                tenant_id="tenant-1",
                parent_id="user-abc",
                is_active=True,
            ),
        )
    assert exc.value.error_code == "personal_cannot_be_parent"


@pytest.mark.asyncio
async def test_create_child_sets_ancestor_ids() -> None:
    """Child inherits parent.ancestor_ids + parent.uid."""
    parent = SimpleNamespace(
        uid="p1",
        ancestor_ids=["root"],
        is_personal=False,
        is_active=True,
    )
    user = SimpleNamespace(
        uid="u1",
        workspace_ids=["p1"],
        workspace_roles={"p1": ["CEO"]},
        save=mock.AsyncMock(),
    )
    child = SimpleNamespace(uid="c1", tenant_id="tenant-1")
    role = SimpleNamespace(name="CEO")

    with (
        mock.patch.object(services, "require_workspace_manage"),
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=parent),
        ),
        mock.patch.object(
            services.User,
            "get_item",
            new=mock.AsyncMock(return_value=user),
        ),
        mock.patch.object(
            services.Workspace,
            "create_item",
            new=mock.AsyncMock(return_value=child),
        ) as create_item,
        mock.patch.object(
            services,
            "_init_workspace_roles",
            new=mock.AsyncMock(return_value=role),
        ),
    ):
        result = await services.create_child_workspace(
            user_data=_user_data(scopes=["manage:sso/usso/workspace?workspace_id=p1"]),
            item=WorkspaceSchema(
                name="Child",
                tenant_id="tenant-1",
                parent_id="p1",
                is_active=True,
            ),
        )

    assert result is child
    kwargs = create_item.await_args.args[0]
    assert kwargs["parent_id"] == "p1"
    assert kwargs["ancestor_ids"] == ["root", "p1"]
    assert kwargs["is_active"] is False
    assert "c1" in user.workspace_ids


@pytest.mark.asyncio
async def test_get_roles_merges_membered_descendant() -> None:
    """Login on parent includes roles from membered active child."""
    user = User.model_construct(
        uid="u1",
        tenant_id="tenant-1",
        roles=[],
        workspace_roles={"p1": ["CEO"], "c1": ["member"]},
        workspace_ids=["p1", "c1"],
        scopes=[],
    )
    parent_role = _role(
        uid="r-p",
        name="CEO",
        scopes=["read:r?workspace_id={workspace_id}"],
        workspace_id="p1",
    )
    child_role = _role(
        uid="r-c",
        name="member",
        scopes=["create:r?workspace_id={workspace_id}"],
        workspace_id="c1",
    )

    def fake_get_query(**kwargs: object) -> mock.Mock:
        query = mock.Mock()
        wid = kwargs.get("workspace_id")
        if wid == "p1":
            query.to_list = mock.AsyncMock(return_value=[parent_role])
        elif wid == "c1":
            query.to_list = mock.AsyncMock(return_value=[child_role])
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
            new=mock.AsyncMock(return_value=["c1"]),
        ),
    ):
        roles = await user.get_roles("p1")

    assert {r.name for r in roles} == {"CEO", "member"}


@pytest.mark.asyncio
async def test_expand_roles_fanout_active_descendants_only() -> None:
    """Parent role scopes fan out to active descendants."""
    user = User.model_construct(
        uid="u1",
        tenant_id="tenant-1",
        scopes=[],
        roles=[],
        workspace_roles={},
        workspace_ids=["p1"],
    )
    parent_role = _role(
        uid="r-p",
        name="CEO",
        scopes=["read:r?workspace_id={workspace_id}"],
        workspace_id="p1",
    )

    with mock.patch(
        "apps.access_control.workspace.services.list_active_descendant_ids",
        new=mock.AsyncMock(return_value=["c1"]),
    ):
        scopes = await token_services.expand_roles_with_fanout(
            user=user,
            workspace_id="p1",
            roles=[parent_role],
        )

    assert set(scopes) == {
        "read:r?workspace_id=p1",
        "read:r?workspace_id=c1",
    }


def test_has_system_workspace_admin_ignores_parent_scoped() -> None:
    """Parent-scoped admin does not count as system admin enter."""
    assert not services.has_system_workspace_admin(
        user_scopes=["admin:sso/usso/workspace?workspace_id=p1"]
    )
    assert services.has_system_workspace_admin(user_scopes=["admin:sso/usso/workspace"])


def test_can_list_tenant_workspaces_for_admin_role_and_manage_scope() -> None:
    """Tenant admin and unscoped workspace managers see every workspace."""
    user_data = _user_data()
    tenant_admin = SimpleNamespace(roles=["admin"])
    assert services.can_list_tenant_workspaces(user=tenant_admin, user_data=user_data)
    # Org-specific role names alone do not grant listing; scopes do.
    org_named = SimpleNamespace(roles=["cds-admin"])
    assert not services.can_list_tenant_workspaces(user=org_named, user_data=user_data)
    member = SimpleNamespace(roles=[])
    assert not services.can_list_tenant_workspaces(user=member, user_data=user_data)
    manager = _user_data(scopes=["manage:sso/usso/workspace"])
    assert services.can_list_tenant_workspaces(user=member, user_data=manager)
    scoped = _user_data(scopes=["manage:sso/usso/workspace?workspace_id=ws-1"])
    assert not services.can_list_tenant_workspaces(user=member, user_data=scoped)


def test_manage_on_ancestor_allows_invite_target() -> None:
    """Manage on ancestor satisfies invite authz for a descendant."""
    workspace = SimpleNamespace(uid="c1", ancestor_ids=["p1"])
    services.require_workspace_manage_on_target_or_ancestor(
        user_data=_user_data(scopes=["manage:sso/usso/workspace?workspace_id=p1"]),
        workspace=workspace,
    )


def test_manage_on_unrelated_denied_for_invite() -> None:
    """Unrelated manage does not authorize invite into another workspace."""
    workspace = SimpleNamespace(uid="c1", ancestor_ids=["p1"])
    with pytest.raises(ForbiddenError) as exc:
        services.require_workspace_manage_on_target_or_ancestor(
            user_data=_user_data(
                scopes=["manage:sso/usso/workspace?workspace_id=other"]
            ),
            workspace=workspace,
        )
    assert exc.value.error_code == "workspace_manage_denied"
