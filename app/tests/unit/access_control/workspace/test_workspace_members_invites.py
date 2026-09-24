"""Unit tests for workspace member add/remove and invitation flows."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi_mongo_base.utils import timezone

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import (
    InvitationStatus,
    WorkspaceInvitationCreateSchema,
)
from server.exceptions import BadRequestError, ForbiddenError, NotFoundError


def _tenant(
    *, workspace_enabled: bool = True, verification_provider: str | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            workspace=SimpleNamespace(
                enabled=workspace_enabled,
                verification_provider=verification_provider,
            ),
        ),
    )


def _user_data(
    *, uid: str = "admin-1", scopes: list[str] | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        user_id=uid,
        uid=uid,
        tenant_id="tenant-1",
        scopes=scopes or ["manage:sso/usso/member"],
    )


def _workspace(*, uid: str = "ws-1", **kwargs: object) -> SimpleNamespace:
    return SimpleNamespace(uid=uid, tenant_id="tenant-1", **kwargs)


@pytest.mark.asyncio
async def test_assert_assignable_role_rejects_unknown_and_escalation() -> None:
    """Unknown roles and roles with uncovered scopes are rejected."""
    with (
        mock.patch.object(
            services.Role, "find_one", new=mock.AsyncMock(return_value=None)
        ),
        pytest.raises(BadRequestError) as missing,
    ):
        await services.assert_assignable_workspace_role(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            role_name="CEO",
        )
    assert missing.value.error_code == "invalid_workspace_role"

    role = SimpleNamespace(
        name="CEO",
        scopes=["admin:sso/usso/workspace", "manage:finance/exchange"],
    )
    with (
        mock.patch.object(
            services.Role, "find_one", new=mock.AsyncMock(return_value=role)
        ),
        pytest.raises(ForbiddenError) as denied,
    ):
        await services.assert_assignable_workspace_role(
            tenant=_tenant(),
            user_data=_user_data(scopes=["manage:sso/usso/workspace"]),
            workspace_id="ws-1",
            role_name="CEO",
        )
    assert denied.value.error_code == "role_scope_insufficient"


@pytest.mark.asyncio
async def test_assert_assignable_role_admin_bypasses_subset_check() -> None:
    """``admin:sso/usso/workspace`` bypasses the scope subset check."""
    role = SimpleNamespace(
        name="member",
        scopes=["create:cds/disclosure?workspace_id={workspace_id}"],
    )
    with mock.patch.object(
        services.Role, "find_one", new=mock.AsyncMock(return_value=role)
    ):
        assigned = await services.assert_assignable_workspace_role(
            tenant=_tenant(),
            user_data=_user_data(scopes=["admin:sso/usso/workspace"]),
            workspace_id="ws-1",
            role_name="member",
        )
    assert assigned is role


def test_require_workspace_enabled_raises_when_disabled() -> None:
    """Disabled workspace feature blocks the caller."""
    with pytest.raises(BadRequestError) as exc:
        services.require_workspace_enabled(_tenant(workspace_enabled=False))
    assert exc.value.error_code == "workspace_not_enabled"


def test_require_workspace_enabled_passes_when_enabled() -> None:
    """Enabled tenants pass through without raising."""
    services.require_workspace_enabled(_tenant(workspace_enabled=True))


@pytest.mark.asyncio
async def test_add_workspace_member_denies_without_manage_scope() -> None:
    """Caller without manage:sso/usso/member cannot add members."""
    with pytest.raises(ForbiddenError) as exc:
        await services.add_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(scopes=["read:sso/usso/member"]),
            workspace_id="ws-1",
            target_user_id="target-1",
            role="member",
        )
    assert exc.value.error_code == "user_manage_denied"


@pytest.mark.asyncio
async def test_add_workspace_member_raises_when_target_missing() -> None:
    """Target user must exist."""
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=_workspace()),
        ),
        mock.patch.object(
            services, "_init_workspace_roles", new=mock.AsyncMock(return_value=None)
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=None)
        ),
        pytest.raises(NotFoundError) as exc,
    ):
        await services.add_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            target_user_id="target-1",
            role="member",
        )
    assert exc.value.error_code == "user_not_found"


@pytest.mark.asyncio
async def test_add_workspace_member_adds_role_and_membership() -> None:
    """Adding a member attaches membership and the requested role once."""
    target = SimpleNamespace(
        uid="target-1",
        name="Target",
        avatar_url=None,
        is_active=True,
        workspace_ids=[],
        workspace_roles={},
        save=mock.AsyncMock(),
        get_identifiers=mock.AsyncMock(return_value=[]),
    )
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=_workspace()),
        ),
        mock.patch.object(
            services, "_init_workspace_roles", new=mock.AsyncMock(return_value=None)
        ),
        mock.patch.object(
            services,
            "assert_assignable_workspace_role",
            new=mock.AsyncMock(return_value=SimpleNamespace(name="member", scopes=[])),
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=target)
        ),
        mock.patch.object(
            services.KYC,
            "get_by_user_id",
            new=mock.AsyncMock(return_value=None),
        ),
    ):
        result = await services.add_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            target_user_id="target-1",
            role="member",
        )

    assert result.uid == "target-1"
    assert result.roles == ["member"]
    assert "ws-1" in target.workspace_ids
    # Saved once for membership attach, once for the role assignment.
    assert target.save.await_count == 2


@pytest.mark.asyncio
async def test_add_workspace_member_is_idempotent_for_existing_role() -> None:
    """Re-adding an existing role does not duplicate it or re-save."""
    target = SimpleNamespace(
        uid="target-1",
        name="Target",
        avatar_url=None,
        is_active=True,
        workspace_ids=["ws-1"],
        workspace_roles={"ws-1": ["member"]},
        save=mock.AsyncMock(),
        get_identifiers=mock.AsyncMock(return_value=[]),
    )
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=_workspace()),
        ),
        mock.patch.object(
            services, "_init_workspace_roles", new=mock.AsyncMock(return_value=None)
        ),
        mock.patch.object(
            services,
            "assert_assignable_workspace_role",
            new=mock.AsyncMock(return_value=SimpleNamespace(name="member", scopes=[])),
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=target)
        ),
        mock.patch.object(
            services.KYC,
            "get_by_user_id",
            new=mock.AsyncMock(return_value=None),
        ),
    ):
        result = await services.add_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            target_user_id="target-1",
            role="member",
        )

    assert result.roles == ["member"]
    target.save.assert_not_awaited()


@pytest.mark.asyncio
async def test_remove_workspace_member_denies_without_manage_scope() -> None:
    """Caller without manage:sso/usso/member cannot remove members."""
    with pytest.raises(ForbiddenError) as exc:
        await services.remove_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(scopes=["read:sso/usso/member"]),
            workspace_id="ws-1",
            target_user_id="target-1",
        )
    assert exc.value.error_code == "user_manage_denied"


@pytest.mark.asyncio
async def test_remove_workspace_member_raises_when_target_missing() -> None:
    """Target user must exist to be removed."""
    with (
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=None)
        ),
        pytest.raises(NotFoundError) as exc,
    ):
        await services.remove_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            target_user_id="target-1",
        )
    assert exc.value.error_code == "user_not_found"


@pytest.mark.asyncio
async def test_remove_workspace_member_clears_membership_and_roles() -> None:
    """Removal drops workspace_id from ids and roles mapping."""
    target = SimpleNamespace(
        uid="target-1",
        workspace_ids=["ws-1", "ws-2"],
        workspace_roles={"ws-1": ["member"], "ws-2": ["member"]},
        save=mock.AsyncMock(),
    )
    with mock.patch.object(
        services.User, "get_item", new=mock.AsyncMock(return_value=target)
    ):
        await services.remove_workspace_member(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            target_user_id="target-1",
        )

    assert target.workspace_ids == ["ws-2"]
    assert "ws-1" not in target.workspace_roles
    target.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_workspace_invitation_rejects_self_invite() -> None:
    """Users cannot invite themselves."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[])
    invitee = SimpleNamespace(uid="admin-1", workspace_ids=[])
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=workspace),
        ),
        mock.patch.object(
            services,
            "require_workspace_manage_on_target_or_ancestor",
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=invitee)
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.create_workspace_invitation(
            tenant=_tenant(),
            user_data=_user_data(uid="admin-1"),
            workspace_id="ws-1",
            data=WorkspaceInvitationCreateSchema(invited_id="admin-1"),
        )
    assert exc.value.error_code == "cannot_invite_self"


@pytest.mark.asyncio
async def test_create_workspace_invitation_rejects_invitee_missing() -> None:
    """Invitee must exist."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[])
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=workspace),
        ),
        mock.patch.object(
            services,
            "require_workspace_manage_on_target_or_ancestor",
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=None)
        ),
        pytest.raises(NotFoundError) as exc,
    ):
        await services.create_workspace_invitation(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            data=WorkspaceInvitationCreateSchema(invited_id="invitee-1"),
        )
    assert exc.value.error_code == "user_not_found"


@pytest.mark.asyncio
async def test_create_workspace_invitation_rejects_existing_member() -> None:
    """Already-member invitees are rejected."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[])
    invitee = SimpleNamespace(uid="invitee-1", workspace_ids=["ws-1"])
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=workspace),
        ),
        mock.patch.object(
            services,
            "require_workspace_manage_on_target_or_ancestor",
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=invitee)
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.create_workspace_invitation(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            data=WorkspaceInvitationCreateSchema(invited_id="invitee-1"),
        )
    assert exc.value.error_code == "already_workspace_member"


@pytest.mark.asyncio
async def test_create_workspace_invitation_rejects_pending_duplicate() -> None:
    """A non-expired pending invitation blocks a new one."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[])
    invitee = SimpleNamespace(uid="invitee-1", workspace_ids=[])
    existing = SimpleNamespace(
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(days=1),
        save=mock.AsyncMock(),
    )
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=workspace),
        ),
        mock.patch.object(
            services,
            "require_workspace_manage_on_target_or_ancestor",
        ),
        mock.patch.object(
            services,
            "assert_assignable_workspace_role",
            new=mock.AsyncMock(return_value=SimpleNamespace(name="member", scopes=[])),
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=invitee)
        ),
        mock.patch.object(
            services.WorkspaceInvitation,
            "find_one",
            new=mock.AsyncMock(return_value=existing),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.create_workspace_invitation(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            data=WorkspaceInvitationCreateSchema(invited_id="invitee-1"),
        )
    assert exc.value.error_code == "invitation_already_pending"


@pytest.mark.asyncio
async def test_create_workspace_invitation_succeeds() -> None:
    """A fresh invitation is created and saved."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[])
    invitee = SimpleNamespace(uid="invitee-1", workspace_ids=[])
    created = SimpleNamespace(save=mock.AsyncMock())

    invitation_cls = mock.MagicMock(return_value=created)
    invitation_cls.find_one = mock.AsyncMock(return_value=None)

    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(return_value=workspace),
        ),
        mock.patch.object(
            services,
            "require_workspace_manage_on_target_or_ancestor",
        ),
        mock.patch.object(
            services,
            "assert_assignable_workspace_role",
            new=mock.AsyncMock(return_value=SimpleNamespace(name="member", scopes=[])),
        ),
        mock.patch.object(
            services.User, "get_item", new=mock.AsyncMock(return_value=invitee)
        ),
        mock.patch.object(services, "WorkspaceInvitation", invitation_cls),
    ):
        result = await services.create_workspace_invitation(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            data=WorkspaceInvitationCreateSchema(invited_id="invitee-1"),
        )

    assert result is created
    invitation_cls.assert_called_once()
    kwargs = invitation_cls.call_args.kwargs
    assert kwargs["workspace_id"] == "ws-1"
    assert kwargs["invited_id"] == "invitee-1"
    assert kwargs["status"] == InvitationStatus.PENDING
    created.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_workspace_invitations_raises_when_workspace_missing() -> None:
    """Listing invitations for an unknown workspace raises."""
    with (
        mock.patch.object(
            services.Workspace, "find_one", new=mock.AsyncMock(return_value=None)
        ),
        pytest.raises(NotFoundError) as exc,
    ):
        await services.list_workspace_invitations(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            status=None,
            offset=0,
            limit=10,
        )
    assert exc.value.error_code == "workspace_not_found"


@pytest.mark.asyncio
async def test_list_workspace_invitations_returns_items() -> None:
    """Listing returns paginated items filtered by status."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[])
    invitation = SimpleNamespace(
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(days=1),
        save=mock.AsyncMock(),
    )
    find_result = mock.Mock()
    find_result.count = mock.AsyncMock(return_value=1)
    sorted_query = mock.Mock()
    sorted_query.skip.return_value = sorted_query
    sorted_query.limit.return_value = sorted_query
    sorted_query.to_list = mock.AsyncMock(return_value=[invitation])
    find_result.sort.return_value = sorted_query

    with (
        mock.patch.object(
            services.Workspace, "find_one", new=mock.AsyncMock(return_value=workspace)
        ),
        mock.patch.object(
            services,
            "require_workspace_manage_on_target_or_ancestor",
        ),
        mock.patch.object(
            services.WorkspaceInvitation, "find", return_value=find_result
        ),
    ):
        items, total = await services.list_workspace_invitations(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            status=InvitationStatus.PENDING,
            offset=0,
            limit=10,
        )

    assert total == 1
    assert items == [invitation]


@pytest.mark.asyncio
async def test_list_my_invitations_returns_items() -> None:
    """A user's own invitations are listed and expired ones refreshed."""
    invitation = SimpleNamespace(
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(days=1),
        save=mock.AsyncMock(),
    )
    find_result = mock.Mock()
    find_result.count = mock.AsyncMock(return_value=1)
    sorted_query = mock.Mock()
    sorted_query.skip.return_value = sorted_query
    sorted_query.limit.return_value = sorted_query
    sorted_query.to_list = mock.AsyncMock(return_value=[invitation])
    find_result.sort.return_value = sorted_query

    with mock.patch.object(
        services.WorkspaceInvitation, "find", return_value=find_result
    ):
        items, total = await services.list_my_invitations(
            tenant=_tenant(),
            user_data=_user_data(uid="invitee-1"),
            status=None,
            offset=0,
            limit=10,
        )

    assert total == 1
    assert items == [invitation]
