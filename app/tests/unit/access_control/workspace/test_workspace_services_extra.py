"""High-value error and delegation coverage for workspace services."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import InvitationStatus, WorkspaceSchema
from server.exceptions import (
    AlreadyExistsError,
    BadRequestError,
    ForbiddenError,
    NotFoundError,
)


def _user_data(*, scopes: list[str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(user_id="user-1", tenant_id="tenant-1", scopes=scopes or [])


@pytest.mark.asyncio
async def test_workspace_create_paths_and_dependency_errors() -> None:
    created = SimpleNamespace(uid="workspace-1")
    with patch.object(
        services.Workspace, "create_item", new=AsyncMock(return_value=created)
    ) as create:
        assert (
            await services.find_or_create_workspace(tenant_id="tenant-1", name="Acme")
            is created
        )
    assert create.await_args.args[0]["slug"]

    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", slug="acme")
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing,
    ):
        await services.create_workspace_by_admin(user_data=_user_data(), item=item)
    assert missing.value.error_code == "user_not_found"

    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=object())),
        patch.object(
            services.Workspace, "find_one", new=AsyncMock(return_value=object())
        ),
        pytest.raises(AlreadyExistsError),
    ):
        await services.create_workspace_by_admin(user_data=_user_data(), item=item)

    workspace = SimpleNamespace(uid="workspace-new")
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=object())),
        patch.object(services.Workspace, "find_one", new=AsyncMock(return_value=None)),
        patch.object(
            services.Workspace, "create_item", new=AsyncMock(return_value=workspace)
        ) as create,
        patch.object(services, "_init_workspace_roles", new=AsyncMock()) as init,
    ):
        assert (
            await services.create_workspace_by_admin(user_data=_user_data(), item=item)
            is workspace
        )
    assert create.await_args.args[0]["meta_data"]["created_by_admin"] is True
    init.assert_awaited_once_with(workspace=workspace)


@pytest.mark.asyncio
async def test_create_workspace_delegation_and_regular_flow() -> None:
    child_item = WorkspaceSchema(
        tenant_id="tenant-1", name="Child", parent_id="parent-1"
    )
    child = SimpleNamespace(uid="child")
    with patch.object(
        services, "create_child_workspace", new=AsyncMock(return_value=child)
    ):
        assert await services.create_workspace(_user_data(), child_item) is child

    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme")
    with (
        patch.object(services, "has_system_workspace_admin", return_value=True),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing_user_as_admin,
    ):
        await services.create_workspace(_user_data(), item)
    assert missing_user_as_admin.value.error_code == "user_not_found"

    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing_user,
    ):
        await services.create_workspace(_user_data(), item)
    assert missing_user.value.error_code == "user_not_found"

    user = SimpleNamespace(workspace_ids=[], workspace_roles={}, save=AsyncMock())
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(services.Tenant, "get_by_uid", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing_tenant,
    ):
        await services.create_workspace(_user_data(), item)
    assert missing_tenant.value.error_code == "tenant_not_found"

    workspace = SimpleNamespace(uid="workspace-1")
    role = SimpleNamespace(name="CEO")
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            services.Tenant, "get_by_uid", new=AsyncMock(return_value=object())
        ),
        patch.object(
            services,
            "find_or_create_workspace",
            new=AsyncMock(return_value=workspace),
        ),
        patch.object(
            services, "_init_workspace_roles", new=AsyncMock(return_value=role)
        ),
        patch.object(services, "_add_user_to_workspace", new=AsyncMock()),
    ):
        assert await services.create_workspace(_user_data(), item) is workspace
    assert user.workspace_roles == {"workspace-1": ["CEO"]}


@pytest.mark.asyncio
async def test_child_role_and_management_branches() -> None:
    item = WorkspaceSchema(tenant_id="tenant-1", name="Child")
    with pytest.raises(BadRequestError) as no_parent:
        await services.create_child_workspace(user_data=_user_data(), item=item)
    assert no_parent.value.error_code == "parent_id_required"

    item.parent_id = "parent-1"
    personal = SimpleNamespace(uid="parent-1", is_personal=True, ancestor_ids=[])
    with (
        patch.object(services, "require_workspace_manage"),
        patch.object(
            services,
            "require_workspace_active",
            new=AsyncMock(return_value=personal),
        ),
        pytest.raises(BadRequestError),
    ):
        await services.create_child_workspace(user_data=_user_data(), item=item)

    item.slug = "child"
    parent = SimpleNamespace(uid="parent-1", is_personal=False, ancestor_ids=[])
    with (
        patch.object(services, "require_workspace_manage"),
        patch.object(
            services,
            "require_workspace_active",
            new=AsyncMock(return_value=parent),
        ),
        patch.object(
            services.Workspace, "find_one", new=AsyncMock(return_value=object())
        ),
        pytest.raises(AlreadyExistsError),
    ):
        await services.create_child_workspace(user_data=_user_data(), item=item)

    workspace = SimpleNamespace(uid="workspace-1", tenant_id="tenant-1")
    existing_role = SimpleNamespace(name="member")
    with patch.object(
        services.Role, "find_one", new=AsyncMock(return_value=existing_role)
    ):
        assert (
            await services._ensure_workspace_role(
                workspace=workspace,
                name="member",
                description="Member",
                scopes=[],
            )
            is existing_role
        )

    tenant = SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(workspace=SimpleNamespace(enabled=True)),
    )
    with (
        patch.object(
            services.Workspace, "find_one", new=AsyncMock(return_value=workspace)
        ),
        patch.object(
            services,
            "_init_workspace_roles",
            new=AsyncMock(return_value=SimpleNamespace(name="CEO")),
        ),
    ):
        assert (
            await services.ensure_management_workspace(tenant=tenant, admin_user=None)
            is workspace
        )
    assert (
        await services.list_membered_active_descendant_ids(
            user=SimpleNamespace(workspace_ids=[]), workspace_id="workspace-1"
        )
        == []
    )


@pytest.mark.asyncio
async def test_workspace_and_invitation_error_branches() -> None:
    with (
        patch.object(services.Workspace, "find_one", new=AsyncMock(return_value=None)),
        pytest.raises(NotFoundError),
    ):
        await services.require_workspace_active(
            tenant_id="tenant-1", workspace_id="missing"
        )

    tenant = SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(workspace=SimpleNamespace(enabled=True)),
    )
    query = MagicMock()
    query.count = AsyncMock(return_value=0)
    query.sort.return_value.skip.return_value.limit.return_value.to_list = AsyncMock(
        return_value=[]
    )
    with patch.object(services.WorkspaceInvitation, "find", return_value=query) as find:
        assert await services.list_my_invitations(
            tenant=tenant,
            user_data=_user_data(),
            status=InvitationStatus.ACCEPTED,
            offset=0,
            limit=10,
        ) == ([], 0)
    assert find.call_args_list[0].args[0]["status"] == InvitationStatus.ACCEPTED

    with pytest.raises(BadRequestError):
        await services.respond_to_invitation(
            tenant=tenant,
            user_data=_user_data(),
            invitation_uid="invite",
            status=InvitationStatus.PENDING,
        )
    with (
        patch.object(
            services.WorkspaceInvitation, "find_one", new=AsyncMock(return_value=None)
        ),
        pytest.raises(NotFoundError),
    ):
        await services.respond_to_invitation(
            tenant=tenant,
            user_data=_user_data(),
            invitation_uid="missing",
            status=InvitationStatus.ACCEPTED,
        )
    foreign = SimpleNamespace(invited_id="other")
    with (
        patch.object(
            services.WorkspaceInvitation,
            "find_one",
            new=AsyncMock(return_value=foreign),
        ),
        pytest.raises(ForbiddenError),
    ):
        await services.respond_to_invitation(
            tenant=tenant,
            user_data=_user_data(),
            invitation_uid="foreign",
            status=InvitationStatus.ACCEPTED,
        )
    closed = SimpleNamespace(
        invited_id="user-1",
        status=InvitationStatus.ACCEPTED,
        expires_at=datetime.now(timezone.tz),
    )
    with (
        patch.object(
            services.WorkspaceInvitation,
            "find_one",
            new=AsyncMock(return_value=closed),
        ),
        pytest.raises(BadRequestError),
    ):
        await services.respond_to_invitation(
            tenant=tenant,
            user_data=_user_data(),
            invitation_uid="closed",
            status=InvitationStatus.ACCEPTED,
        )
