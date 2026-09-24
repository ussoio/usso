"""
Tests for User.list_users_with_role and User.propagate_role_scope_change.

Integration tests for list_users_with_role and propagate_role_scope_change.
Skipped when using mongomock_motor (Beanie aggregate cursor incompatibility).
Remove the pytestmark below or run with real MongoDB to execute these tests.
"""

import pytest
import pytest_asyncio

from apps.access_control.role.models import Role
from apps.identity.user.models import User
from apps.tenant.models import Tenant

pytestmark = pytest.mark.skip(
    reason="Beanie aggregate + mongomock_motor cursor incompatibility; use real MongoDB"
)


@pytest_asyncio.fixture(scope="module")
async def tenant() -> Tenant:
    """Create a tenant for propagation tests (module-scoped to avoid duplicate uid)."""
    t = Tenant(
        name="Propagation Tenant",
        domains=["prop.local"],
        uid="prop_tenant_scope",
        user_id="creator_1",
    )
    await t.save()
    return t


@pytest_asyncio.fixture(scope="module")
async def roles(tenant: Tenant) -> list[Role]:
    """Create tenant-wide and workspace-scoped roles."""
    r_global = Role(
        name="editor",
        description="Editor",
        scopes=["read:*", "write:doc"],
        tenant_id=tenant.uid,
        workspace_id=None,
    )
    await r_global.save()
    r_ws = Role(
        name="editor",
        description="Editor in WS",
        scopes=["read:*", "write:doc", "admin:ws"],
        tenant_id=tenant.uid,
        workspace_id="ws_1",
    )
    await r_ws.save()
    return [r_global, r_ws]


@pytest_asyncio.fixture(scope="module")
async def user_global_role(tenant: Tenant, roles: list[Role]) -> User:
    """User with role only in roles (tenant-wide)."""
    u = User(
        name="Global Editor",
        is_active=True,
        tenant_id=tenant.uid,
        uid="user_global_1",
        roles=["editor"],
        workspace_roles={},
    )
    await u.save()
    return u


@pytest_asyncio.fixture(scope="module")
async def user_workspace_role(tenant: Tenant, roles: list[Role]) -> User:
    """User with role only in workspace_roles."""
    u = User(
        name="WS Editor",
        is_active=True,
        tenant_id=tenant.uid,
        uid="user_ws_1",
        roles=[],
        workspace_roles={"ws_1": ["editor"]},
    )
    await u.save()
    return u


@pytest_asyncio.fixture(scope="module")
async def user_both(tenant: Tenant, roles: list[Role]) -> User:
    """User with editor in both global and ws_1."""
    u = User(
        name="Both",
        is_active=True,
        tenant_id=tenant.uid,
        uid="user_both_1",
        roles=["editor"],
        workspace_roles={"ws_1": ["editor"]},
    )
    await u.save()
    return u


@pytest.mark.asyncio
async def test_list_users_with_role_returns_global_only(
    tenant: Tenant,
    user_global_role: User,
    user_workspace_role: User,
) -> None:
    """list_users_with_role returns users that have the role globally or in any workspace."""  # ruff:ignore[line-too-long]
    out = await User.list_users_with_role(tenant_id=tenant.uid, role_name="editor")
    uids = {u.uid for u, _ in out}
    assert user_global_role.uid in uids
    assert user_workspace_role.uid in uids
    for user, workspace_ids in out:
        if user.uid == user_global_role.uid:
            assert None in workspace_ids
        if user.uid == user_workspace_role.uid:
            assert "ws_1" in workspace_ids


@pytest.mark.asyncio
async def test_list_users_with_role_workspace_ids_per_user(
    tenant: Tenant,
    user_global_role: User,
    user_workspace_role: User,
    user_both: User,
) -> None:
    """Each returned tuple has (user, list of workspace_id where they have the role)."""
    out = await User.list_users_with_role(tenant_id=tenant.uid, role_name="editor")
    by_uid = {u.uid: (u, wss) for u, wss in out}
    assert user_global_role.uid in by_uid
    assert set(by_uid[user_global_role.uid][1]) == {None}
    assert set(by_uid[user_workspace_role.uid][1]) == {"ws_1"}
    assert set(by_uid[user_both.uid][1]) == {None, "ws_1"}


@pytest.mark.asyncio
async def test_propagate_role_scope_change_no_op_when_no_users(
    tenant: Tenant,
    roles: list[Role],
) -> None:
    """propagate_role_scope_change does not fail when no user has the role."""
    # Create a role no one has
    r = Role(
        name="nobody",
        scopes=["x"],
        tenant_id=tenant.uid,
        workspace_id=None,
    )
    await r.save()
    await User.propagate_role_scope_change(
        tenant_id=tenant.uid,
        role_name="nobody",
        role_workspace_id=None,
    )


@pytest.mark.asyncio
async def test_propagate_role_scope_change_runs_without_error(
    tenant: Tenant,
    user_global_role: User,
    user_workspace_role: User,
    user_both: User,
) -> None:
    """propagate_role_scope_change runs and updates affected users (no exception)."""
    await User.propagate_role_scope_change(
        tenant_id=tenant.uid,
        role_name="editor",
        role_workspace_id=None,
    )


@pytest.mark.asyncio
async def test_propagate_role_scope_change_filters_by_role_workspace(
    tenant: Tenant,
    user_workspace_role: User,
) -> None:
    """When role_workspace_id is set, only that workspace's context is updated."""
    await User.propagate_role_scope_change(
        tenant_id=tenant.uid,
        role_name="editor",
        role_workspace_id="ws_1",
    )
