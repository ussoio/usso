"""Focused unit coverage for workspace route handlers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.models import TenantScopedEntity

from apps.access_control.workspace import models, routes, schemas
from apps.identity.auth.enums import AuthIdentifier
from server.exceptions import BadRequestError, UnauthorizedError


def _user_data(**overrides: object) -> SimpleNamespace:
    values = {
        "uid": "user-1",
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "roles": [],
        "scopes": [],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _tenant(
    *, enabled: bool = True, allow_member_create: bool = True
) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            workspace=SimpleNamespace(
                enabled=enabled,
                allow_member_create=allow_member_create,
            )
        ),
    )


def _request() -> MagicMock:
    request = MagicMock()
    request.headers = {"user-agent": "pytest"}
    return request


def test_get_list_filter_queries_uses_broadest_scope() -> None:
    router = routes.WorkspaceRouter()
    user = _user_data(scopes=["read:sso/usso/workspace"])
    matches = [{"tenant_id": "tenant-1"}]
    with (
        patch.object(routes.authorization, "get_scope_filters", return_value=matches),
        patch.object(
            routes.authorization,
            "broadest_scope_filter",
            return_value={"tenant_id": "tenant-1"},
        ) as broadest,
    ):
        assert router.get_list_filter_queries(user=user) == {"tenant_id": "tenant-1"}
    broadest.assert_called_once_with(matches)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored_user", "auth_roles", "auth_scopes", "expected_filter"),
    [
        (SimpleNamespace(roles=["admin"], workspace_ids=["ws-1"]), [], [], {}),
        (
            SimpleNamespace(roles=[], workspace_ids=["ws-1"]),
            [],
            [],
            {"uid__in": ["ws-1"], "is_active": True},
        ),
        (None, [], [], {"uid__in": [], "is_active": True}),
        (SimpleNamespace(roles=[], workspace_ids=[]), ["admin"], [], {}),
        (
            SimpleNamespace(roles=[], workspace_ids=[]),
            [],
            ["manage:sso/usso/workspace"],
            {},
        ),
    ],
)
async def test_list_items_applies_admin_or_membership_filter(
    stored_user: object,
    auth_roles: list[str],
    auth_scopes: list[str],
    expected_filter: dict,
) -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    list_items = AsyncMock(return_value="page")
    with (
        patch.object(
            router,
            "get_user",
            new=AsyncMock(
                return_value=_user_data(roles=auth_roles, scopes=auth_scopes)
            ),
        ),
        patch.object(router, "_list_items", new=list_items),
        patch.object(
            routes.User, "get_by_uid", new=AsyncMock(return_value=stored_user)
        ),
    ):
        assert await router.list_items(request, offset=2, limit=4) == "page"
    list_items.assert_awaited_once_with(
        request=request, offset=2, limit=4, **expected_filter
    )


@pytest.mark.asyncio
async def test_list_items_passes_business_type_to_database_filter() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    list_items = AsyncMock(return_value="page")
    stored_user = SimpleNamespace(roles=["admin"], workspace_ids=[])
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=_user_data())),
        patch.object(router, "_list_items", new=list_items),
        patch.object(
            routes.User,
            "get_by_uid",
            new=AsyncMock(return_value=stored_user),
        ),
    ):
        assert (
            await router.list_items(
                request,
                offset=0,
                limit=10,
                workspace_type="business",
            )
            == "page"
        )

    list_items.assert_awaited_once_with(
        request=request,
        offset=0,
        limit=10,
        type="business",
    )


@pytest.mark.asyncio
async def test_mine_items_filters_memberships_and_active_state() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    list_items = AsyncMock(return_value="page")
    stored_user = SimpleNamespace(workspace_ids=["ws-1", "ws-2"])
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=_user_data())),
        patch.object(router, "_list_items", new=list_items),
        patch.object(
            routes.User, "get_by_uid", new=AsyncMock(return_value=stored_user)
        ),
    ):
        assert await router.mine_items(request, 1, 5, False) == "page"
    list_items.assert_awaited_once_with(
        request=request,
        offset=1,
        limit=5,
        uid__in=["ws-1", "ws-2"],
        is_active=False,
    )


@pytest.mark.asyncio
async def test_create_item_rejects_disabled_workspace_feature() -> None:
    router = routes.WorkspaceRouter()
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(enabled=False)),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await router.create_item(_request(), schemas.WorkspaceCreateSchema(name="Acme"))
    assert exc.value.error_code == "workspace_not_enabled"


@pytest.mark.asyncio
async def test_create_item_rejects_when_member_create_disabled() -> None:
    router = routes.WorkspaceRouter()
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(allow_member_create=False)),
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=_user_data())),
        pytest.raises(BadRequestError) as exc,
    ):
        await router.create_item(_request(), schemas.WorkspaceCreateSchema(name="Acme"))
    assert exc.value.error_code == "workspace_member_create_disabled"


@pytest.mark.asyncio
async def test_create_item_provisions_for_system_admin() -> None:
    """POST /workspaces with system admin scope provisions without joining."""
    router = routes.WorkspaceRouter()
    request = _request()
    user = _user_data(scopes=["admin:sso/usso/workspace"])
    created = SimpleNamespace(uid="ws-1")
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(allow_member_create=False)),
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(
            routes.services,
            "create_workspace_provision",
            new=AsyncMock(return_value=created),
        ) as provision,
        patch.object(
            routes.services,
            "create_workspace",
            new=AsyncMock(),
        ) as join,
    ):
        result = await router.create_item(
            request, schemas.WorkspaceCreateSchema(name="Acme")
        )
    assert result is created
    provision.assert_awaited_once()
    join.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_mine_item_joins_even_for_system_admin() -> None:
    """POST /workspaces/mine always uses the join path."""
    router = routes.WorkspaceRouter()
    request = _request()
    user = _user_data(scopes=["admin:sso/usso/workspace"])
    created = SimpleNamespace(uid="ws-1")
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(allow_member_create=False)),
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(
            routes.services,
            "create_workspace",
            new=AsyncMock(return_value=created),
        ) as join,
        patch.object(
            routes.services,
            "create_workspace_provision",
            new=AsyncMock(),
        ) as provision,
    ):
        result = await router.create_mine_item(
            request, schemas.WorkspaceCreateSchema(name="Acme")
        )
    assert result is created
    join.assert_awaited_once()
    provision.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_mine_item_rejects_when_member_create_disabled() -> None:
    router = routes.WorkspaceRouter()
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=_tenant(allow_member_create=False)),
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=_user_data())),
        pytest.raises(BadRequestError) as exc,
    ):
        await router.create_mine_item(
            _request(), schemas.WorkspaceCreateSchema(name="Acme")
        )
    assert exc.value.error_code == "workspace_member_create_disabled"


@pytest.mark.asyncio
async def test_create_item_builds_tenant_scoped_schema() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    user = _user_data()
    created = SimpleNamespace(uid="ws-1")
    with (
        patch.object(router, "get_tenant", new=AsyncMock(return_value=_tenant())),
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(
            routes.services,
            "create_workspace",
            new=AsyncMock(return_value=created),
        ) as create,
    ):
        result = await router.create_item(
            request, schemas.WorkspaceCreateSchema(name="Acme", parent_id="parent-1")
        )
    assert result is created
    payload = create.await_args.args[1]
    assert create.await_args.args[0] is user
    assert payload.tenant_id == "tenant-1"
    assert payload.name == "Acme"
    assert payload.parent_id == "parent-1"


@pytest.mark.asyncio
async def test_retrieve_item_gets_and_authorizes_workspace() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    user = _user_data()
    item = SimpleNamespace(uid="ws-1")
    get_item = AsyncMock(return_value=item)
    authorize = AsyncMock()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_item", new=get_item),
        patch.object(router, "get_owner_id", new=MagicMock(return_value="owner-1")),
        patch.object(router, "authorize", new=authorize),
    ):
        assert await router.retrieve_item(request, "ws-1") is item
    get_item.assert_awaited_once_with(
        uid="ws-1", tenant_id="tenant-1", **{router.owner_attr: None}
    )
    authorize.assert_awaited_once_with(
        action="read", user=user, filter_data={"owner_id": "owner-1"}
    )


@pytest.mark.asyncio
async def test_list_and_search_workspace_users() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    user = _user_data()
    tenant = _tenant()
    member = schemas.WorkspaceMemberSchema(uid="member-1", roles=["member"])
    search_result = schemas.UserSearchResultSchema(
        uid="member-1",
        matched_type=AuthIdentifier.EMAIL,
        matched_identifier="member@example.com",
    )
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            router,
            "get_item",
            new=AsyncMock(return_value=SimpleNamespace(uid="ws-1")),
        ),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(
            routes.services,
            "list_workspace_members",
            new=AsyncMock(return_value=([member], 1)),
        ) as list_members,
        patch.object(
            routes.services,
            "search_users_by_identifier_prefix",
            new=AsyncMock(return_value=([search_result], 1)),
        ) as search_users,
    ):
        listed = await router.list_workspace_users(request, "ws-1", 2, 3)
        searched = await router.search_workspace_users(
            request,
            "ws-1",
            "mem",
            AuthIdentifier.EMAIL,
            4,
            5,
        )
    assert listed.items == [member]
    assert (listed.total, listed.offset, listed.limit) == (1, 2, 3)
    assert searched.items == [search_result]
    list_members.assert_awaited_once_with(
        workspace_id="ws-1", tenant_id="tenant-1", offset=2, limit=3
    )
    search_users.assert_awaited_once_with(
        tenant=tenant,
        user_data=user,
        workspace_id="ws-1",
        identifier="mem",
        identifier_type=AuthIdentifier.EMAIL,
        offset=4,
        limit=5,
    )


def test_workspace_login_route_registered_on_path() -> None:
    """POST /workspaces/{uid}/login is registered (REST path-based login)."""
    router = routes.WorkspaceRouter()
    login_routes = [
        route
        for route in router.router.routes
        if hasattr(route, "path") and route.path.endswith("/{uid}/login")
    ]
    assert login_routes
    assert "POST" in (login_routes[0].methods or set())


@pytest.mark.asyncio
async def test_login_workspace_uses_body_refresh_token() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    payload = SimpleNamespace(uid="user-1")
    session = object()
    response = object()
    tenant = SimpleNamespace(
        refresh_auth=SimpleNamespace(
            user_data_from_token=MagicMock(return_value=payload)
        )
    )
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "check_session_validity", new=AsyncMock(return_value=session)
        ) as check,
        patch.object(
            routes,
            "build_workspace_switch_response",
            new=AsyncMock(return_value=response),
        ) as build,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
    ):
        result = await router.login_workspace(
            request, "ws-1", schemas.WorkspaceLoginBodySchema(refresh_token="token")
        )
    assert result is response
    tenant.refresh_auth.user_data_from_token.assert_called_once_with(
        "token", raise_exception=True, expected_token_type="refresh"
    )
    check.assert_awaited_once_with(refresh_payload=payload)
    build.assert_awaited_once_with(
        request=request,
        tenant=tenant,
        payload=payload,
        session=session,
        workspace_id="ws-1",
        user_agent="pytest",
        ip="127.0.0.1",
    )


@pytest.mark.asyncio
async def test_login_workspace_requires_cookie_or_body_refresh_token() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    refresh_auth = MagicMock(return_value=None)
    tenant = SimpleNamespace(refresh_auth=refresh_auth)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await router.login_workspace(request, "ws-1", None)
    assert exc.value.error_code == "refresh_token_required"
    refresh_auth.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_member_and_workspace_invitation_handlers_delegate() -> None:
    router = routes.WorkspaceRouter()
    request = _request()
    tenant = _tenant()
    user = _user_data()
    member_data = schemas.WorkspaceMemberCreateSchema(user_id="member-1", role="owner")
    invite_data = schemas.WorkspaceInvitationCreateSchema(
        invited_id="member-1", role="member", expires_in_days=3
    )
    member = schemas.WorkspaceMemberSchema(uid="member-1", roles=["owner"])
    invitation = SimpleNamespace(uid="invite-1")
    with (
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(
            routes.services,
            "add_workspace_member",
            new=AsyncMock(return_value=member),
        ) as add,
        patch.object(
            routes.services, "remove_workspace_member", new=AsyncMock()
        ) as remove,
        patch.object(
            routes.services,
            "create_workspace_invitation",
            new=AsyncMock(return_value=invitation),
        ) as invite,
        patch.object(
            routes.services,
            "list_workspace_invitations",
            new=AsyncMock(return_value=([], 0)),
        ) as list_invites,
    ):
        assert await router.add_workspace_member(request, "ws-1", member_data) is member
        removed = await router.remove_workspace_member(request, "ws-1", "member-1")
        assert removed.status_code == 204
        assert (
            await router.create_workspace_invitation(request, "ws-1", invite_data)
            is invitation
        )
        page = await router.list_workspace_invitations(
            request, "ws-1", schemas.InvitationStatus.PENDING, 1, 2
        )
    assert page.total == 0
    add.assert_awaited_once_with(
        tenant=tenant,
        user_data=user,
        workspace_id="ws-1",
        target_user_id="member-1",
        role="owner",
    )
    remove.assert_awaited_once_with(
        tenant=tenant,
        user_data=user,
        workspace_id="ws-1",
        target_user_id="member-1",
    )
    invite.assert_awaited_once_with(
        tenant=tenant, user_data=user, workspace_id="ws-1", data=invite_data
    )
    list_invites.assert_awaited_once_with(
        tenant=tenant,
        user_data=user,
        workspace_id="ws-1",
        status=schemas.InvitationStatus.PENDING,
        offset=1,
        limit=2,
    )


@pytest.mark.asyncio
async def test_invitation_router_lists_and_responds() -> None:
    router = routes.InvitationRouter()
    request = _request()
    tenant = _tenant()
    user = _user_data()
    updated = SimpleNamespace(uid="invite-1")
    data = schemas.WorkspaceInvitationUpdateSchema(
        status=schemas.InvitationStatus.ACCEPTED
    )
    with (
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(
            routes.services,
            "list_my_invitations",
            new=AsyncMock(return_value=([], 0)),
        ) as list_mine,
        patch.object(
            routes.services,
            "respond_to_invitation",
            new=AsyncMock(return_value=updated),
        ) as respond,
    ):
        page = await router.list_items(request, schemas.InvitationStatus.PENDING, 3, 4)
        assert await router.update_item(request, "invite-1", data) is updated
    assert (page.total, page.offset, page.limit) == (0, 3, 4)
    list_mine.assert_awaited_once_with(
        tenant=tenant,
        user_data=user,
        status=schemas.InvitationStatus.PENDING,
        offset=3,
        limit=4,
    )
    respond.assert_awaited_once_with(
        tenant=tenant,
        user_data=user,
        invitation_uid="invite-1",
        status=schemas.InvitationStatus.ACCEPTED,
    )


def test_workspace_queryset_adds_uid_membership_filter() -> None:
    base_query = {"tenant_id": "tenant-1", "is_deleted": False}
    with patch.object(
        TenantScopedEntity, "get_queryset", return_value=base_query.copy()
    ) as get_queryset:
        result = models.Workspace.get_queryset(
            tenant_id="tenant-1", uid__in=("ws-1", "ws-2")
        )
    assert result == {
        "tenant_id": "tenant-1",
        "is_deleted": False,
        "uid": {"$in": ["ws-1", "ws-2"]},
    }
    get_queryset.assert_called_once_with(tenant_id="tenant-1")


def test_workspace_queryset_without_uid_filter_and_personal_property() -> None:
    with patch.object(
        TenantScopedEntity,
        "get_queryset",
        return_value={"tenant_id": "tenant-1"},
    ):
        assert models.Workspace.get_queryset(tenant_id="tenant-1") == {
            "tenant_id": "tenant-1"
        }
    personal = models.Workspace.model_construct(meta_data={"kind": "personal"})
    organization = models.Workspace.model_construct(meta_data={"kind": "organization"})
    missing_metadata = models.Workspace.model_construct(meta_data=None)
    assert personal.is_personal is True
    assert organization.is_personal is False
    assert missing_metadata.is_personal is False


def test_workspace_queryset_filters_name_and_organization_code() -> None:
    """Admin workspace directory search matches name and organization code."""
    query = models.Workspace.get_queryset(
        tenant_id="tenant-1",
        name_like=" Acme ",
        organization_code_like="103",
    )
    assert query["tenant_id"] == "tenant-1"
    assert query["name"]["$regex"] == "Acme"
    assert query["organization_code"]["$regex"] == "103"


def test_workspace_router_resource_path_matches_catalog() -> None:
    """Workspace authorize path is sso/usso/workspace, not PROJECT_NAME/workspace."""
    assert routes.WorkspaceRouter().resource_path == "sso/usso/workspace"
