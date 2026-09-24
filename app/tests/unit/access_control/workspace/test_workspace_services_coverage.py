"""Additional unit coverage for workspace service helper branches."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import InvitationStatus, WorkspaceSchema
from server.exceptions import BadRequestError, ForbiddenError, NotFoundError


def _tenant(
    *, enabled: bool = True, verification_provider: str | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            workspace=SimpleNamespace(
                enabled=enabled,
                user_search_enabled=True,
                verification_provider=verification_provider,
            )
        ),
    )


def _user_data(*, scopes: list[str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        user_id="user-1",
        tenant_id="tenant-1",
        scopes=scopes or [],
    )


@pytest.mark.asyncio
async def test_create_workspace_by_admin_missing_and_existing() -> None:
    """Admin creation validates the user and reactivates a matching workspace."""
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", organization_code="103")
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.create_workspace_by_admin(user_data=_user_data(), item=item)
    assert exc.value.error_code == "user_not_found"

    existing = SimpleNamespace(uid="ws-1", is_active=False, save=AsyncMock())
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=object())),
        patch.object(
            services.Workspace, "find_one", new=AsyncMock(return_value=existing)
        ),
    ):
        result = await services.create_workspace_by_admin(
            user_data=_user_data(), item=item
        )
    assert result is existing
    assert existing.is_active is True
    existing.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_workspace_by_admin_creates_roles() -> None:
    """A fresh admin workspace is active and receives default roles."""
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", slug="acme")
    workspace = SimpleNamespace(uid="ws-1")
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=object())),
        patch.object(services.Workspace, "find_one", new=AsyncMock(return_value=None)),
        patch.object(
            services.Workspace, "create_item", new=AsyncMock(return_value=workspace)
        ) as create,
        patch.object(services, "_init_workspace_roles", new=AsyncMock()) as init_roles,
    ):
        result = await services.create_workspace_by_admin(
            user_data=_user_data(), item=item
        )
    assert result is workspace
    assert create.await_args.args[0]["is_active"] is True
    init_roles.assert_awaited_once_with(workspace=workspace)


@pytest.mark.asyncio
async def test_create_workspace_routes_child_and_does_not_divert_admin() -> None:
    """Top-level creation delegates child early; system-admin still joins."""
    child_item = WorkspaceSchema(
        tenant_id="tenant-1", name="Child", parent_id="parent-1"
    )
    child = SimpleNamespace(uid="child-1")
    with patch.object(
        services, "create_child_workspace", new=AsyncMock(return_value=child)
    ) as create_child:
        assert await services.create_workspace(_user_data(), child_item) is child
    create_child.assert_awaited_once_with(user_data=_user_data(), item=child_item)

    admin_item = WorkspaceSchema(
        tenant_id="tenant-1", name="Acme", organization_code="103"
    )
    user = SimpleNamespace(workspace_ids=[], workspace_roles={}, save=AsyncMock())
    workspace = SimpleNamespace(uid="ws-join", is_active=True)
    role = SimpleNamespace(name="CEO")
    with (
        patch.object(services, "has_system_workspace_admin", return_value=True),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            services.Tenant, "get_by_uid", new=AsyncMock(return_value=_tenant())
        ),
        patch.object(
            services,
            "find_or_create_simple_organization_workspace",
            new=AsyncMock(return_value=workspace),
        ),
        patch.object(
            services, "_init_workspace_roles", new=AsyncMock(return_value=role)
        ),
        patch.object(services, "_add_user_to_workspace", new=AsyncMock()) as add_member,
        patch.object(
            services,
            "create_workspace_provision",
            new=AsyncMock(),
        ) as provision,
    ):
        assert (
            await services.create_workspace(
                _user_data(scopes=["admin:sso/usso/workspace"]), admin_item
            )
            is workspace
        )
    provision.assert_not_awaited()
    add_member.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_workspace_provision_creates_without_membership() -> None:
    """Tenant-catalog provision does not add the caller to workspace_ids."""
    item = WorkspaceSchema(
        tenant_id="tenant-1", name="Acme", organization_code="103"
    )
    user = SimpleNamespace(uid="user-1")
    workspace = SimpleNamespace(uid="ws-1")
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(services.Workspace, "find_one", new=AsyncMock(return_value=None)),
        patch.object(
            services.Workspace, "create_item", new=AsyncMock(return_value=workspace)
        ) as create,
        patch.object(services, "_init_workspace_roles", new=AsyncMock()) as init_roles,
        patch.object(services, "_add_user_to_workspace", new=AsyncMock()) as add_member,
    ):
        result = await services.create_workspace_provision(
            user_data=_user_data(), item=item
        )
    assert result is workspace
    assert create.await_args.args[0]["is_active"] is True
    init_roles.assert_awaited_once_with(workspace=workspace)
    add_member.assert_not_awaited()
    # Alias keeps working
    assert services.create_workspace_by_admin is services.create_workspace_provision


@pytest.mark.asyncio
async def test_find_or_create_simple_organization_workspace() -> None:
    """Local org workspace create reuses existing rows and creates when missing."""
    existing = SimpleNamespace(uid="ws-1")
    with patch.object(
        services.Workspace, "find_one", new=AsyncMock(return_value=existing)
    ):
        assert (
            await services.find_or_create_simple_organization_workspace(
                tenant_id="tenant-1",
                organization_code="103",
            )
            is existing
        )

    created = SimpleNamespace(uid="ws-new")
    with (
        patch.object(services.Workspace, "find_one", new=AsyncMock(return_value=None)),
        patch.object(
            services.Workspace, "create_item", new=AsyncMock(return_value=created)
        ) as create,
    ):
        result = await services.find_or_create_simple_organization_workspace(
            tenant_id="tenant-1",
            organization_code="103",
            name="Acme",
            slug="acme",
        )
    assert result is created
    item = create.await_args.args[0]
    assert item["organization_code"] == "103"
    assert item["name"] == "Acme"
    assert item["slug"] == "acme"
    assert item["is_active"] is False


@pytest.mark.asyncio
async def test_create_workspace_rejects_missing_tenant() -> None:
    """Organization create requires a resolvable tenant before verification."""
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", organization_code="103")
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(
            services.User, "get_item", new=AsyncMock(return_value=SimpleNamespace())
        ),
        patch.object(services.Tenant, "get_by_uid", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.create_workspace(_user_data(), item)
    assert exc.value.error_code == "tenant_not_found"


@pytest.mark.asyncio
async def test_create_workspace_regular_validation_branches() -> None:
    """Organization creation validates the user, membership, and optional verifier."""
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", organization_code="103")
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing,
    ):
        await services.create_workspace(_user_data(), item)
    assert missing.value.error_code == "user_not_found"

    workspace = SimpleNamespace(uid="ws-1", is_active=True)
    member = SimpleNamespace(workspace_ids=["ws-1"])
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=member)),
        patch.object(
            services.Tenant, "get_by_uid", new=AsyncMock(return_value=_tenant())
        ),
        patch.object(
            services,
            "find_or_create_simple_organization_workspace",
            new=AsyncMock(return_value=workspace),
        ),
    ):
        assert await services.create_workspace(_user_data(), item) is workspace

    non_member = SimpleNamespace(workspace_ids=[], workspace_roles={}, save=AsyncMock())
    verifier = MagicMock()
    verifier.ensure_workspace = AsyncMock(return_value=workspace)
    verifier.verify_create = AsyncMock(
        side_effect=BadRequestError(
            error_code="user_is_not_ceo",
            detail="User is not CEO",
            message={"en": "no", "fa": "no"},
        )
    )
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=non_member)),
        patch.object(
            services.Tenant,
            "get_by_uid",
            new=AsyncMock(return_value=_tenant(verification_provider="ice_ceo")),
        ),
        patch(
            "apps.access_control.workspace.verification.get_verifier",
            return_value=verifier,
        ),
        pytest.raises(BadRequestError) as not_ceo,
    ):
        await services.create_workspace(_user_data(), item)
    assert not_ceo.value.error_code == "user_is_not_ceo"
    verifier.ensure_workspace.assert_awaited_once()
    verifier.verify_create.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_workspace_skips_verifier_when_provider_unset() -> None:
    """Default tenant config creates without calling a verification plugin."""
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", organization_code="103")
    workspace = SimpleNamespace(uid="ws-1", is_active=False, save=AsyncMock())
    user = SimpleNamespace(workspace_ids=[], workspace_roles={}, save=AsyncMock())
    role = SimpleNamespace(name="CEO")
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            services.Tenant, "get_by_uid", new=AsyncMock(return_value=_tenant())
        ),
        patch.object(
            services,
            "find_or_create_simple_organization_workspace",
            new=AsyncMock(return_value=workspace),
        ),
        patch(
            "apps.access_control.workspace.verification.get_verifier"
        ) as get_verifier,
        patch.object(
            services, "_init_workspace_roles", new=AsyncMock(return_value=role)
        ),
        patch.object(services, "_add_user_to_workspace", new=AsyncMock()) as add_user,
    ):
        assert await services.create_workspace(_user_data(), item) is workspace
    get_verifier.assert_not_called()
    assert workspace.is_active is True
    workspace.save.assert_awaited_once()
    add_user.assert_awaited_once_with(user=user, workspace_id="ws-1")
    assert user.workspace_roles == {"ws-1": ["CEO"]}
    user.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_workspace_runs_provider_then_activates() -> None:
    """Configured verification provider runs org resolve + verify before join."""
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", organization_code="103")
    workspace = SimpleNamespace(uid="ws-1", is_active=False, save=AsyncMock())
    user = SimpleNamespace(workspace_ids=[], workspace_roles={}, save=AsyncMock())
    role = SimpleNamespace(name="CEO")
    verifier = MagicMock()
    verifier.ensure_workspace = AsyncMock(return_value=workspace)
    verifier.verify_create = AsyncMock()
    with (
        patch.object(services, "has_system_workspace_admin", return_value=False),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            services.Tenant,
            "get_by_uid",
            new=AsyncMock(return_value=_tenant(verification_provider="ice_ceo")),
        ),
        patch(
            "apps.access_control.workspace.verification.get_verifier",
            return_value=verifier,
        ) as get_verifier,
        patch.object(
            services, "_init_workspace_roles", new=AsyncMock(return_value=role)
        ),
        patch.object(services, "_add_user_to_workspace", new=AsyncMock()) as add_user,
    ):
        assert await services.create_workspace(_user_data(), item) is workspace
    get_verifier.assert_called_once_with("ice_ceo")
    verifier.ensure_workspace.assert_awaited_once()
    verifier.verify_create.assert_awaited_once()
    assert workspace.is_active is True
    workspace.save.assert_awaited_once()
    add_user.assert_awaited_once_with(user=user, workspace_id="ws-1")
    assert user.workspace_roles == {"ws-1": ["CEO"]}
    user.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_workspace_role_initializers_existing_and_create() -> None:
    """Role initialization reuses existing roles and creates missing defaults."""
    workspace = SimpleNamespace(uid="ws-1", tenant_id="tenant-1")
    existing = SimpleNamespace(name="member")
    with patch.object(services.Role, "find_one", new=AsyncMock(return_value=existing)):
        assert (
            await services._ensure_workspace_role(
                workspace=workspace,
                name="member",
                description="Member",
                scopes=["read:x"],
            )
            is existing
        )

    created = SimpleNamespace(name="CEO")
    with (
        patch.object(services.Role, "find_one", new=AsyncMock(return_value=None)),
        patch.object(
            services.Role, "create_item", new=AsyncMock(return_value=created)
        ) as create,
    ):
        assert (
            await services._ensure_workspace_role(
                workspace=workspace,
                name="CEO",
                description="Chief",
                scopes=["manage:x"],
            )
            is created
        )
    assert create.await_args.args[0]["workspace_id"] == "ws-1"

    member = SimpleNamespace(name="member")
    ceo = SimpleNamespace(name="CEO")
    with patch.object(
        services,
        "_ensure_workspace_role",
        new=AsyncMock(side_effect=[member, ceo]),
    ) as ensure:
        assert await services._init_workspace_roles(workspace=workspace) is ceo
    assert ensure.await_count == 2

    owner = SimpleNamespace(name="owner")
    with (
        patch.object(services.Role, "find_one", new=AsyncMock(return_value=None)),
        patch.object(
            services.Role, "create_item", new=AsyncMock(return_value=owner)
        ) as create_owner,
    ):
        assert (
            await services._init_personal_workspace_roles(workspace=workspace) is owner
        )
    assert create_owner.await_args.args[0]["name"] == "owner"


@pytest.mark.asyncio
async def test_require_workspace_active_missing_active_and_inactive() -> None:
    """Workspace lookup distinguishes missing, inactive, and active records."""
    with (
        patch.object(services.Workspace, "find_one", new=AsyncMock(return_value=None)),
        pytest.raises(NotFoundError) as missing,
    ):
        await services.require_workspace_active(
            tenant_id="tenant-1", workspace_id="ws-1"
        )
    assert missing.value.error_code == "workspace_not_found"

    inactive = SimpleNamespace(uid="ws-1", is_active=False)
    with (
        patch.object(
            services.Workspace, "find_one", new=AsyncMock(return_value=inactive)
        ),
        pytest.raises(ForbiddenError) as denied,
    ):
        await services.require_workspace_active(
            tenant_id="tenant-1", workspace_id="ws-1"
        )
    assert denied.value.error_code == "workspace_not_active"

    active = SimpleNamespace(uid="ws-1", is_active=True)
    with patch.object(
        services.Workspace, "find_one", new=AsyncMock(return_value=active)
    ):
        assert (
            await services.require_workspace_active(
                tenant_id="tenant-1", workspace_id="ws-1"
            )
            is active
        )


@pytest.mark.asyncio
async def test_expire_if_needed_handles_naive_and_current_invitations() -> None:
    """Expired naive timestamps are normalized while future invites stay pending."""
    expired = SimpleNamespace(
        status=InvitationStatus.PENDING,
        expires_at=datetime(2000, 1, 1),
        save=AsyncMock(),
    )
    assert services._ensure_aware(expired.expires_at).tzinfo == timezone.tz
    await services._expire_if_needed(expired)
    assert expired.status == InvitationStatus.EXPIRED
    expired.save.assert_awaited_once()

    accepted = SimpleNamespace(
        status=InvitationStatus.ACCEPTED,
        expires_at=datetime.now(timezone.tz),
        save=AsyncMock(),
    )
    await services._expire_if_needed(accepted)
    accepted.save.assert_not_awaited()


@pytest.mark.asyncio
async def test_search_prefix_short_and_no_matches() -> None:
    """Search rejects short prefixes and returns early when identifiers miss."""
    workspace = SimpleNamespace(uid="ws-1", ancestor_ids=[], is_active=True)
    with (
        patch.object(
            services,
            "require_workspace_active",
            new=AsyncMock(return_value=workspace),
        ),
        patch.object(services, "require_workspace_manage_on_target_or_ancestor"),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.search_users_by_identifier_prefix(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            identifier=" a ",
            identifier_type=None,
            offset=0,
            limit=10,
        )
    assert exc.value.error_code == "search_prefix_too_short"

    query = MagicMock(to_list=AsyncMock(return_value=[]))
    with (
        patch.object(
            services,
            "require_workspace_active",
            new=AsyncMock(return_value=workspace),
        ),
        patch.object(services, "require_workspace_manage_on_target_or_ancestor"),
        patch.object(services.UserIdentifier, "find", return_value=query) as find,
    ):
        assert await services.search_users_by_identifier_prefix(
            tenant=_tenant(),
            user_data=_user_data(),
            workspace_id="ws-1",
            identifier=" a.b ",
            identifier_type=None,
            offset=0,
            limit=10,
        ) == ([], 0)
    assert find.call_args.args[0]["identifier"]["$regex"] == r"^a\.b"
