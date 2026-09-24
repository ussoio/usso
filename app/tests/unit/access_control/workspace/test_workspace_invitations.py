"""Unit tests for workspace invitations and searchable user discovery."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi_mongo_base.utils import timezone
from pydantic import ValidationError

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import (
    InvitationStatus,
    WorkspaceInvitationCreateSchema,
    WorkspaceInvitationUpdateSchema,
)
from server.exceptions import BadRequestError, ForbiddenError


def _tenant(
    *, workspace_enabled: bool = True, user_search: bool = True
) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            workspace=SimpleNamespace(
                enabled=workspace_enabled,
                user_search_enabled=user_search,
            )
        ),
    )


def _user_data(
    *, uid: str = "inviter-1", scopes: list[str] | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        user_id=uid,
        uid=uid,
        tenant_id="tenant-1",
        scopes=scopes or ["manage:sso/usso/workspace?workspace_id=ws-1"],
    )


def test_invitation_expires_in_days_max_30() -> None:
    """expires_in_days cannot exceed one month."""
    with pytest.raises(ValidationError):
        WorkspaceInvitationCreateSchema(invited_id="u2", expires_in_days=31)


def test_invitation_update_accepts_status_enum() -> None:
    """Respond schema accepts accepted/rejected."""
    assert (
        WorkspaceInvitationUpdateSchema(status=InvitationStatus.ACCEPTED).status
        == InvitationStatus.ACCEPTED
    )


def test_require_workspace_manage_denies_without_scope() -> None:
    """Manage check fails when JWT lacks manage on the workspace."""
    with pytest.raises(ForbiddenError) as exc:
        services.require_workspace_manage(
            user_data=_user_data(scopes=["read:sso/*/*?workspace_id=ws-1"]),
            workspace_id="ws-1",
        )
    assert exc.value.error_code == "workspace_manage_denied"


def test_require_workspace_manage_allows_manage_scope() -> None:
    """Manage scope on the workspace passes."""
    services.require_workspace_manage(
        user_data=_user_data(),
        workspace_id="ws-1",
    )


@pytest.mark.asyncio
async def test_require_workspace_active_blocks_inactive() -> None:
    """Inactive workspaces are rejected."""
    with (
        mock.patch.object(
            services.Workspace,
            "find_one",
            new=mock.AsyncMock(
                return_value=SimpleNamespace(uid="ws-1", is_active=False)
            ),
        ),
        pytest.raises(ForbiddenError) as exc,
    ):
        await services.require_workspace_active(
            tenant_id="tenant-1", workspace_id="ws-1"
        )
    assert exc.value.error_code == "workspace_not_active"


@pytest.mark.asyncio
async def test_search_requires_user_search_enabled() -> None:
    """Tenant must enable user_search_enabled for discovery."""
    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(
                return_value=SimpleNamespace(
                    uid="ws-1", is_active=True, ancestor_ids=[]
                )
            ),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.search_users_by_identifier_prefix(
            tenant=_tenant(user_search=False),
            user_data=_user_data(),
            workspace_id="ws-1",
            identifier="ab",
            identifier_type=None,
            offset=0,
            limit=10,
        )
    assert exc.value.error_code == "user_search_not_enabled"


@pytest.mark.asyncio
async def test_search_filters_by_searchable_flags() -> None:
    """Only searchable user + searchable identifier are returned."""
    ident_ok = SimpleNamespace(
        user_id="u-ok",
        type="email",
        identifier="alice@example.com",
    )
    ident_hidden_user = SimpleNamespace(
        user_id="u-hidden",
        type="email",
        identifier="alice2@example.com",
    )
    user_ok = SimpleNamespace(
        uid="u-ok",
        name="Alice",
        avatar_url=None,
        searchable=True,
    )

    with (
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(
                return_value=SimpleNamespace(
                    uid="ws-1", is_active=True, ancestor_ids=[]
                )
            ),
        ),
        mock.patch.object(
            services.UserIdentifier,
            "find",
            return_value=mock.Mock(
                to_list=mock.AsyncMock(return_value=[ident_ok, ident_hidden_user])
            ),
        ),
        mock.patch.object(
            services.User,
            "find",
            return_value=mock.Mock(to_list=mock.AsyncMock(return_value=[user_ok])),
        ),
    ):
        items, total = await services.search_users_by_identifier_prefix(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            identifier="ali",
            identifier_type=None,
            offset=0,
            limit=10,
        )

    assert total == 1
    assert items[0].uid == "u-ok"
    assert items[0].matched_identifier == "alice@example.com"


@pytest.mark.asyncio
async def test_respond_reject_invitation() -> None:
    """Invitee can reject a pending invitation."""
    invitation = SimpleNamespace(
        uid="inv-1",
        invited_id="invitee-1",
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(days=1),
        workspace_id="ws-1",
        role="member",
        save=mock.AsyncMock(),
    )

    with mock.patch.object(
        services.WorkspaceInvitation,
        "find_one",
        new=mock.AsyncMock(return_value=invitation),
    ):
        result = await services.respond_to_invitation(
            tenant=_tenant(),
            user_data=_user_data(uid="invitee-1", scopes=[]),
            invitation_uid="inv-1",
            status=InvitationStatus.REJECTED,
        )

    assert result.status == InvitationStatus.REJECTED
    invitation.save.assert_awaited()


@pytest.mark.asyncio
async def test_respond_accept_adds_membership() -> None:
    """Accepting adds workspace_ids and workspace_roles."""
    invitation = SimpleNamespace(
        uid="inv-1",
        invited_id="invitee-1",
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(days=1),
        workspace_id="ws-1",
        role="member",
        save=mock.AsyncMock(),
    )
    user = SimpleNamespace(
        uid="invitee-1",
        workspace_ids=[],
        workspace_roles={},
        save=mock.AsyncMock(),
    )

    with (
        mock.patch.object(
            services.WorkspaceInvitation,
            "find_one",
            new=mock.AsyncMock(return_value=invitation),
        ),
        mock.patch.object(
            services,
            "require_workspace_active",
            new=mock.AsyncMock(
                return_value=SimpleNamespace(uid="ws-1", is_active=True)
            ),
        ),
        mock.patch.object(
            services.User,
            "get_item",
            new=mock.AsyncMock(return_value=user),
        ),
    ):
        result = await services.respond_to_invitation(
            tenant=_tenant(),
            user_data=_user_data(uid="invitee-1", scopes=[]),
            invitation_uid="inv-1",
            status=InvitationStatus.ACCEPTED,
        )

    assert result.status == InvitationStatus.ACCEPTED
    assert "ws-1" in user.workspace_ids
    assert user.workspace_roles["ws-1"] == ["member"]
    assert result.joined_at is not None


@pytest.mark.asyncio
async def test_expire_pending_invitation() -> None:
    """Pending invitations past expires_at become expired."""
    invitation = SimpleNamespace(
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) - timedelta(minutes=1),
        save=mock.AsyncMock(),
    )
    result = await services._expire_if_needed(invitation)
    assert result.status == InvitationStatus.EXPIRED
    invitation.save.assert_awaited()
