"""Unit tests for tenant management workspace provisioning."""

from types import SimpleNamespace
from unittest import mock

import pytest

from apps.access_control.workspace import services as workspace_services


def _tenant(*, enabled: bool = True, uid: str = "tenant-1") -> SimpleNamespace:
    return SimpleNamespace(
        uid=uid,
        name="Example Tenant",
        config=SimpleNamespace(workspace=SimpleNamespace(enabled=enabled)),
    )


@pytest.mark.asyncio
async def test_ensure_management_workspace_noop_when_disabled() -> None:
    """Do not create a management workspace when workspace feature is off."""
    tenant = _tenant(enabled=False)
    admin = SimpleNamespace(
        uid="admin-1",
        tenant_id="tenant-1",
        workspace_ids=[],
        workspace_roles={},
        save=mock.AsyncMock(),
    )

    with mock.patch.object(
        workspace_services.Workspace,
        "find_one",
        new=mock.AsyncMock(),
    ) as find_one:
        result = await workspace_services.ensure_management_workspace(
            tenant=tenant, admin_user=admin
        )

    assert result is None
    find_one.assert_not_awaited()
    admin.save.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_management_workspace_creates_active_workspace() -> None:
    """Tenant create provisions management workspace with uid == tenant.uid."""
    tenant = _tenant(enabled=True, uid="tenant-abc")
    admin = SimpleNamespace(
        uid="admin-1",
        tenant_id="tenant-abc",
        workspace_ids=[],
        workspace_roles={},
        save=mock.AsyncMock(),
    )
    workspace = SimpleNamespace(uid="tenant-abc", tenant_id="tenant-abc")
    workspace.save = mock.AsyncMock(return_value=workspace)
    manager_role = SimpleNamespace(name="CEO")

    workspace_cls = mock.MagicMock(return_value=workspace)
    workspace_cls.find_one = mock.AsyncMock(return_value=None)

    with (
        mock.patch(
            "apps.access_control.workspace.services.Workspace",
            workspace_cls,
        ),
        mock.patch.object(
            workspace_services,
            "_init_workspace_roles",
            new=mock.AsyncMock(return_value=manager_role),
        ),
    ):
        result = await workspace_services.ensure_management_workspace(
            tenant=tenant, admin_user=admin
        )

    assert result is workspace
    workspace_cls.assert_called_once()
    kwargs = workspace_cls.call_args.kwargs
    assert kwargs["uid"] == "tenant-abc"
    assert kwargs["tenant_id"] == "tenant-abc"
    assert kwargs["name"] == "management"
    assert kwargs["slug"] == "management-tenant-abc"
    assert kwargs["is_active"] is True
    assert kwargs["meta_data"] == {"kind": "management"}
    assert "tenant-abc" in admin.workspace_ids
    assert admin.workspace_roles["tenant-abc"] == ["CEO"]
    admin.save.assert_awaited()


@pytest.mark.asyncio
async def test_ensure_management_workspace_is_idempotent() -> None:
    """Existing management workspace membership is not duplicated."""
    tenant = _tenant(enabled=True, uid="tenant-abc")
    admin = SimpleNamespace(
        uid="admin-1",
        tenant_id="tenant-abc",
        workspace_ids=["tenant-abc"],
        workspace_roles={"tenant-abc": ["CEO"]},
        save=mock.AsyncMock(),
    )
    existing = SimpleNamespace(uid="tenant-abc", tenant_id="tenant-abc")
    manager_role = SimpleNamespace(name="CEO")

    with (
        mock.patch.object(
            workspace_services.Workspace,
            "find_one",
            new=mock.AsyncMock(return_value=existing),
        ),
        mock.patch.object(
            workspace_services,
            "_init_workspace_roles",
            new=mock.AsyncMock(return_value=manager_role),
        ),
    ):
        result = await workspace_services.ensure_management_workspace(
            tenant=tenant, admin_user=admin
        )

    assert result is existing
    admin.save.assert_not_awaited()
    assert admin.workspace_ids == ["tenant-abc"]
    assert admin.workspace_roles == {"tenant-abc": ["CEO"]}
