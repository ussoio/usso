"""Focused method-level unit coverage for identity user models."""

# ruff: file-ignore[line-too-long]

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.models import TenantScopedEntity, TenantUserEntity
from fastapi_mongo_base.utils import timezone

from apps.identity.auth.enums import AuthIdentifier, AuthSecret
from apps.identity.user import models


def _user(**kwargs: object) -> models.User:
    values = {
        "uid": "user-1",
        "tenant_id": "tenant-1",
        "roles": [],
        "scopes": [],
        "workspace_roles": {},
        "workspace_ids": [],
        "is_active": False,
    }
    values.update(kwargs)
    return models.User.model_construct(**values)


def _query(items: list[object]) -> MagicMock:
    query = MagicMock()
    query.sort.return_value = query
    query.limit.return_value = query
    query.skip.return_value = query
    query.to_list = AsyncMock(return_value=items)
    return query


def test_credential_get_queryset_expiry_branches() -> None:
    """Open-ended expiry filters combine safely with an existing OR filter."""
    now = datetime.now(timezone.tz)
    with patch.object(
        TenantUserEntity,
        "get_queryset",
        return_value={"tenant_id": "tenant-1"},
    ):
        assert models.Credential.get_queryset(tenant_id="tenant-1") == {
            "tenant_id": "tenant-1"
        }
        query = models.Credential.get_queryset(
            tenant_id="tenant-1", expires_at_from=now
        )
    assert query["$or"] == [
        {"expires_at": None},
        {"expires_at": {"$gte": now}},
    ]

    with patch.object(
        TenantUserEntity,
        "get_queryset",
        return_value={"$or": [{"method": "password"}], "$and": [{"x": 1}]},
    ):
        query = models.Credential.get_queryset(expires_at_from=now)
    assert query["$and"][0] == {"x": 1}
    assert {"$or": [{"method": "password"}]} in query["$and"]
    assert {"$or": [{"expires_at": None}, {"expires_at": {"$gte": now}}]} in query[
        "$and"
    ]


@pytest.mark.asyncio
async def test_get_tenant_cached_and_get_workspaces() -> None:
    """Tenant is cached while workspace lookup delegates to its query object."""
    user = _user()
    tenant = SimpleNamespace(uid="tenant-1")
    with patch.object(
        models.Tenant, "get_by_uid", new=AsyncMock(return_value=tenant)
    ) as get_tenant:
        assert await user.get_tenant() is tenant
        assert await user.get_tenant() is tenant
    get_tenant.assert_awaited_once_with("tenant-1")

    workspace = SimpleNamespace(uid="ws-1")
    query = _query([workspace])
    with patch.object(models.Workspace, "get_query", return_value=query) as get_query:
        assert await user.get_workspaces() == [workspace]
    get_query.assert_called_once_with(tenant_id="tenant-1")


@pytest.mark.asyncio
async def test_get_scopes_and_effective_scopes() -> None:
    """Direct and role scopes are unioned; API helper normalizes None to a list."""
    user = _user(scopes=["direct"])
    roles = [
        SimpleNamespace(scopes=["role", "direct"]),
        SimpleNamespace(scopes=["other"]),
    ]
    with patch.object(
        models.User, "get_roles", new=AsyncMock(return_value=roles)
    ) as get_roles:
        assert set(await user.get_scopes("ws-1")) == {"direct", "role", "other"}
    get_roles.assert_awaited_once_with("ws-1")

    with patch.object(models.User, "get_scopes", new=AsyncMock(return_value=None)):
        assert await user.get_effective_scopes_for_api() == []


@pytest.mark.asyncio
async def test_get_roles_tenant_workspace_descendants_and_deduplication() -> None:
    """Role resolution loads each context and deduplicates roles by uid."""
    user = _user(
        roles=["member"],
        workspace_roles={"ws-1": ["CEO"], "child-1": ["member"], "empty": []},
    )
    tenant_role = SimpleNamespace(uid="role-1", name="member", scopes=[])
    workspace_role = SimpleNamespace(uid="role-2", name="CEO", scopes=[])
    duplicate = SimpleNamespace(uid="role-1", name="member", scopes=[])
    calls: list[dict] = []

    def get_query(**kwargs: object) -> MagicMock:
        calls.append(kwargs)
        if kwargs["workspace_id"] is None:
            return _query([tenant_role])
        if kwargs["workspace_id"] == "ws-1":
            return _query([workspace_role])
        return _query([duplicate])

    with (
        patch.object(models.Role, "get_query", side_effect=get_query),
        patch(
            "apps.access_control.workspace.services.list_membered_active_descendant_ids",
            new=AsyncMock(return_value=["child-1", "empty"]),
        ),
    ):
        result = await user.get_roles("ws-1")
    assert {role.uid for role in result} == {"role-1", "role-2"}
    assert {call["workspace_id"] for call in calls} == {None, "ws-1", "child-1"}


@pytest.mark.asyncio
async def test_sessions_and_identifiers_cache_and_refresh() -> None:
    """Related collections use their cache unless a refresh is explicitly requested."""
    user = _user()
    session = SimpleNamespace(uid="session-1")
    session_query = _query([session])
    with patch.object(
        models.AuthSession, "get_query", return_value=session_query
    ) as get:
        assert await user.get_sessions() == [session]
        assert await user.get_sessions() == [session]
    get.assert_called_once()

    email = SimpleNamespace(type="email", identifier="alice@example.com")
    username = SimpleNamespace(type="username", identifier="alice")
    identifier_query = _query([email, username])
    with patch.object(
        models.UserIdentifier, "get_query", return_value=identifier_query
    ) as get:
        assert await user.get_identifiers() == [email, username]
        assert await user.get_identifiers() == [email, username]
        assert await user.get_identifiers(not_cached=True) == [email, username]
    assert get.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifiers", "expected"),
    [
        ([SimpleNamespace(type="username", identifier="alice")], "alice"),
        ([SimpleNamespace(type="email", identifier="a@example.com")], "a@example.com"),
        ([SimpleNamespace(type="phone", identifier="09120000000")], "09120000000"),
        ([], "user-1"),
    ],
)
async def test_get_username_precedence(
    identifiers: list[object], expected: str
) -> None:
    """Username falls back through email, phone, then uid."""
    user = _user()
    with patch.object(
        models.User, "get_identifiers", new=AsyncMock(return_value=identifiers)
    ):
        assert await user.get_username() == expected


@pytest.mark.asyncio
async def test_get_credentials_filters_expiry_and_uses_cache() -> None:
    """Credential lookup excludes expired values and normalizes naive datetimes."""
    user = _user()
    now = datetime.now(timezone.tz)
    valid = SimpleNamespace(expires_at=None, method=AuthSecret.PASSWORD)
    future_naive = SimpleNamespace(
        expires_at=(now + timedelta(hours=1)).replace(tzinfo=None),
        method=AuthSecret.PASSWORD,
    )
    future_aware = SimpleNamespace(
        expires_at=now + timedelta(hours=2), method=AuthSecret.PASSWORD
    )
    expired = SimpleNamespace(
        expires_at=now - timedelta(seconds=1), method=AuthSecret.PASSWORD
    )
    query = _query([valid, future_naive, future_aware, expired])
    with patch.object(models.Credential, "get_query", return_value=query) as get:
        assert await user.get_credentials(AuthSecret.PASSWORD) == [
            valid,
            future_naive,
            future_aware,
        ]
        assert await user.get_credentials(AuthSecret.PASSWORD) == [
            valid,
            future_naive,
            future_aware,
        ]
    get.assert_called_once_with(
        tenant_id="tenant-1",
        user_id="user-1",
        is_deleted=False,
        is_active=True,
        method=AuthSecret.PASSWORD,
    )


@pytest.mark.asyncio
async def test_profile_last_credential_and_activity() -> None:
    """Profile/credential delegates and cross-resource last activity are covered."""
    user = _user()
    profile = SimpleNamespace(uid="profile-1")
    credential = SimpleNamespace(uid="cred-1")
    with (
        patch.object(
            models.Profile, "get_by_user_id", new=AsyncMock(return_value=profile)
        ) as get_profile,
        patch.object(
            models.Credential, "find_one", new=AsyncMock(return_value=credential)
        ) as find_credential,
    ):
        assert await user.get_profile() is profile
        assert await user.get_last_used_credential() is credential
    get_profile.assert_awaited_once_with(tenant_id="tenant-1", user_id="user-1")
    assert find_credential.await_args.args[0]["last_used_at"] == {"$ne": None}

    earlier = datetime.now(timezone.tz) - timedelta(hours=2)
    latest = earlier + timedelta(hours=1)
    with (
        patch.object(
            models.AuthSession,
            "get_query",
            return_value=_query([SimpleNamespace(last_used_at=earlier)]),
        ),
        patch.object(
            models.APIKey,
            "get_query",
            return_value=_query([SimpleNamespace(last_used_at=latest)]),
        ),
        patch.object(
            models.Agent,
            "get_query",
            return_value=_query([SimpleNamespace(last_used_at=earlier)]),
        ),
    ):
        assert await user.get_last_activity() == latest

    with (
        patch.object(models.AuthSession, "get_query", return_value=_query([])),
        patch.object(models.APIKey, "get_query", return_value=_query([])),
        patch.object(models.Agent, "get_query", return_value=_query([])),
    ):
        assert await user.get_last_activity() is None


@pytest.mark.asyncio
async def test_properties_activate_and_permission_propagation() -> None:
    """Transient properties work and permission updates fan out to all auth objects."""
    user = _user(
        roles=["member"],
        workspace_roles={"ws-1": ["CEO"]},
    )
    tenant = object()
    identifier = object()
    credential = object()
    user.tenant = tenant
    user.current_identifier = identifier
    user.credentials = [credential]
    assert user.tenant is tenant
    assert user.current_identifier is identifier
    assert user.credentials == [credential]

    save = AsyncMock()
    object.__setattr__(user, "save", save)
    await user.activate()
    assert user.is_active is True
    save.assert_awaited_once_with()

    with (
        patch.object(
            models.User, "get_scopes", new=AsyncMock(side_effect=[["new"], ["cap"]])
        ) as get_scopes,
        patch.object(
            models.AuthSession,
            "update_user_sessions_permissions",
            new=AsyncMock(return_value=3),
        ) as sessions,
        patch.object(
            models.APIKey, "cap_user_api_keys_scopes", new=AsyncMock()
        ) as keys,
        patch.object(models.Agent, "cap_user_agents_scopes", new=AsyncMock()) as agents,
    ):
        assert await user.update_permissions_and_sessions(workspace_id="ws-1") == 3
    assert get_scopes.await_count == 2
    assert sessions.await_args.kwargs["new_roles"] == ["CEO"]
    assert keys.await_args.kwargs["user_scopes"] == ["cap"]
    assert agents.await_args.kwargs["workspace_id"] == "ws-1"


@pytest.mark.asyncio
async def test_to_detailed_schema_populates_related_fields() -> None:
    """Detailed response refreshes identifiers and exposes credential methods only."""
    user = _user()
    response = SimpleNamespace(identifiers=[], credential_methods=[])
    identifiers = [SimpleNamespace(identifier="alice")]
    credentials = [SimpleNamespace(method=AuthSecret.PASSWORD)]
    with (
        patch.object(models.UserResponse, "model_validate", return_value=response),
        patch.object(
            models.User, "get_identifiers", new=AsyncMock(return_value=identifiers)
        ) as get_ids,
        patch.object(
            models.User, "get_credentials", new=AsyncMock(return_value=credentials)
        ),
    ):
        assert await user.to_detailed_schema() is response
    get_ids.assert_awaited_once_with(not_cached=True)
    assert response.identifiers == identifiers
    assert response.credential_methods == [AuthSecret.PASSWORD]


@pytest.mark.asyncio
async def test_list_users_with_role_maps_workspace_ids() -> None:
    """Role aggregation strips its helper field and validates each user."""
    document = {
        "uid": "user-1",
        "tenant_id": "tenant-1",
        "roles": ["member"],
        "_workspace_ids_for_role": [None, "ws-1"],
    }
    user = _user(roles=["member"])
    with (
        patch.object(
            models, "aggregate_to_list", new=AsyncMock(return_value=[document])
        ) as aggregate,
        patch.object(models.User, "model_validate", return_value=user),
    ):
        result = await models.User.list_users_with_role(
            tenant_id="tenant-1", role_name="member"
        )
    assert result == [(user, [None, "ws-1"])]
    assert "_workspace_ids_for_role" not in document
    assert aggregate.await_args.args[1][0] == {
        "$match": {"tenant_id": "tenant-1", "is_deleted": False}
    }


@pytest.mark.asyncio
async def test_propagate_role_scope_change_empty_and_filtered_pairs() -> None:
    """Role scope propagation returns early or updates only matching contexts."""
    with (
        patch.object(
            models.User, "list_users_with_role", new=AsyncMock(return_value=[])
        ),
        patch.object(models.Role, "get_query") as get_roles,
    ):
        await models.User.propagate_role_scope_change(
            tenant_id="tenant-1", role_name="CEO", role_workspace_id=None
        )
    get_roles.assert_not_called()

    user = _user(workspace_roles={"ws-1": ["CEO"], "ws-2": ["member"]})
    roles = [
        SimpleNamespace(workspace_id=None, name="tenant", scopes=["tenant:read"]),
        SimpleNamespace(workspace_id="ws-1", name="CEO", scopes=["ws:manage"]),
    ]
    with (
        patch.object(
            models.User,
            "list_users_with_role",
            new=AsyncMock(return_value=[(user, ["ws-1", "ws-2"])]),
        ),
        patch.object(models.Role, "get_query", return_value=_query(roles)),
    ):
        update_permissions = AsyncMock(return_value=1)
        object.__setattr__(user, "update_permissions_and_sessions", update_permissions)
        await models.User.propagate_role_scope_change(
            tenant_id="tenant-1", role_name="CEO", role_workspace_id="ws-1"
        )
    update_permissions.assert_awaited_once()
    kwargs = update_permissions.await_args.kwargs
    assert kwargs["workspace_id"] == "ws-1"
    assert set(kwargs["new_scopes"]) == {"ws:manage"}


@pytest.mark.asyncio
async def test_delete_item_soft_deletes_relations_then_parent() -> None:
    """Deleting a user soft-deletes identifiers, credentials, and sessions."""
    operations: list[AsyncMock] = []

    def finder(_: dict) -> MagicMock:
        operation = AsyncMock(return_value=None)
        operations.append(operation)
        return SimpleNamespace(update_many=MagicMock(return_value=operation()))

    user = _user()
    with (
        patch.object(models.UserIdentifier, "find", side_effect=finder),
        patch.object(models.Credential, "find", side_effect=finder),
        patch.object(models.AuthSession, "find", side_effect=finder),
        patch.object(
            TenantScopedEntity,
            "delete_item",
            new=AsyncMock(return_value=user),
        ) as parent_delete,
    ):
        assert await models.User.delete_item(user) is user
    assert len(operations) == 3
    assert all(operation.await_count == 1 for operation in operations)
    parent_delete.assert_awaited_once_with(user)


@pytest.mark.asyncio
async def test_hard_delete_cascades_belongings_and_sole_workspaces() -> None:
    """hard_delete soft-deletes belongings and sole-member workspaces."""
    from apps.identity.kyc.models import KYC
    from apps.identity.legal.models import LegalAcceptance
    from apps.identity.referral.models import ReferralCode

    operations: list[AsyncMock] = []

    def finder(_: dict) -> MagicMock:
        operation = AsyncMock(return_value=None)
        operations.append(operation)
        return SimpleNamespace(update_many=MagicMock(return_value=operation()))

    sole_ws = SimpleNamespace(uid="ws-sole")
    shared_ws = SimpleNamespace(uid="ws-shared")
    user = _user(workspace_ids=["ws-sole", "ws-shared"], workspace_roles={"ws-sole": ["owner"]})

    def total_count(**kwargs: object) -> int:
        workspace_ids_in = kwargs.get("workspace_ids_in") or []
        if workspace_ids_in == ["ws-sole"]:
            return 1
        if workspace_ids_in == ["ws-shared"]:
            return 2
        return 0

    def get_workspace(*, uid: str, tenant_id: str, **_: object) -> object:
        return sole_ws if uid == "ws-sole" else shared_ws

    with (
        patch.object(KYC, "find", side_effect=finder),
        patch.object(models.Profile, "find", side_effect=finder),
        patch.object(models.APIKey, "find", side_effect=finder),
        patch.object(models.Agent, "find", side_effect=finder),
        patch.object(ReferralCode, "find", side_effect=finder),
        patch.object(LegalAcceptance, "find", side_effect=finder),
        patch.object(
            models.User, "total_count", new=AsyncMock(side_effect=total_count)
        ),
        patch.object(
            models.Workspace, "get_item", new=AsyncMock(side_effect=get_workspace)
        ) as get_item,
        patch.object(
            models.Workspace, "delete_item", new=AsyncMock(return_value=sole_ws)
        ) as ws_delete,
        patch.object(
            models.User, "delete_item", new=AsyncMock(return_value=user)
        ) as soft_delete,
    ):
        assert await models.User.hard_delete(user) is user

    assert len(operations) == 6
    assert all(operation.await_count == 1 for operation in operations)
    get_item.assert_awaited_once_with(uid="ws-sole", tenant_id="tenant-1")
    ws_delete.assert_awaited_once_with(sole_ws)
    soft_delete.assert_awaited_once_with(user)


@pytest.mark.asyncio
async def test_hard_delete_skips_workspace_when_shared() -> None:
    """Shared workspaces are left intact; only soft-delete of the user runs."""
    from apps.identity.kyc.models import KYC
    from apps.identity.legal.models import LegalAcceptance
    from apps.identity.referral.models import ReferralCode

    def finder(_: dict) -> MagicMock:
        return SimpleNamespace(update_many=MagicMock(return_value=AsyncMock()()))

    user = _user(workspace_ids=["ws-shared"])
    with (
        patch.object(KYC, "find", side_effect=finder),
        patch.object(models.Profile, "find", side_effect=finder),
        patch.object(models.APIKey, "find", side_effect=finder),
        patch.object(models.Agent, "find", side_effect=finder),
        patch.object(ReferralCode, "find", side_effect=finder),
        patch.object(LegalAcceptance, "find", side_effect=finder),
        patch.object(models.User, "total_count", new=AsyncMock(return_value=3)),
        patch.object(models.Workspace, "delete_item", new=AsyncMock()) as ws_delete,
        patch.object(
            models.User, "delete_item", new=AsyncMock(return_value=user)
        ) as soft_delete,
    ):
        assert await models.User.hard_delete(user) is user

    ws_delete.assert_not_awaited()
    soft_delete.assert_awaited_once_with(user)


@pytest.mark.asyncio
async def test_list_and_count_identifier_filter_pipelines() -> None:
    """Identifier-filtered listing/counting build regex, pagination, and zero paths."""
    user = _user()
    with (
        patch.object(
            models.User, "get_queryset", return_value={"tenant_id": "tenant-1"}
        ),
        patch.object(
            models, "aggregate_to_list", new=AsyncMock(return_value=[{"uid": "user-1"}])
        ) as aggregate,
        patch.object(models.User, "model_validate", return_value=user),
    ):
        result = await models.User._list_items_with_identifier_filter(
            tenant_id="tenant-1",
            identifier_type=AuthIdentifier.EMAIL,
            identifier="ali",
            offset=2,
            limit=5,
        )
    assert result == [user]
    pipeline = aggregate.await_args.args[1]
    assert pipeline[-1] == {"$limit": 5}
    assert pipeline[2]["$match"]["identifiers"]["$elemMatch"]["identifier"] == {
        "$regex": "ali",
        "$options": "i",
    }

    with (
        patch.object(models.User, "get_queryset", return_value={}),
        patch.object(models, "aggregate_to_list", new=AsyncMock(return_value=[])),
    ):
        assert (
            await models.User._total_count_with_identifier_filter(
                identifier_type=AuthIdentifier.EMAIL
            )
            == 0
        )
    with (
        patch.object(models.User, "get_queryset", return_value={}),
        patch.object(
            models,
            "aggregate_to_list",
            new=AsyncMock(return_value=[{"total": 7}]),
        ),
    ):
        assert (
            await models.User._total_count_with_identifier_filter(identifier="alice")
            == 7
        )


@pytest.mark.asyncio
async def test_list_total_combined_joins_identifiers_in_one_aggregation() -> None:
    response = SimpleNamespace(
        uid="user-1", identifiers=[SimpleNamespace(type="phone")]
    )
    aggregate_result = [{"items": [{"uid": "user-1"}], "metadata": [{"total": 1}]}]
    with (
        patch.object(
            models.User, "get_queryset", return_value={"tenant_id": "tenant-1"}
        ),
        patch.object(
            models, "aggregate_to_list", new=AsyncMock(return_value=aggregate_result)
        ) as aggregate,
        patch.object(models.UserResponse, "model_validate", return_value=response),
    ):
        items, total = await models.User.list_total_combined(
            tenant_id="tenant-1",
            offset=10,
            limit=5,
            identifier_type=AuthIdentifier.PHONE,
        )

    assert items == [response]
    assert total == 1
    aggregate.assert_awaited_once()
    pipeline = aggregate.await_args.args[1]
    assert pipeline[1]["$lookup"]["from"] == "UserIdentifier"
    assert all(stage.get("$lookup", {}).get("from") != "KYC" for stage in pipeline)
    assert pipeline[2] == {
        "$match": {"identifiers": {"$elemMatch": {"type": AuthIdentifier.PHONE}}}
    }
    assert pipeline[3]["$facet"]["items"] == [
        {"$sort": {"created_at": -1}},
        {"$skip": 10},
        {"$limit": 5},
    ]


@pytest.mark.asyncio
async def test_public_list_and_count_choose_parent_or_identifier_helpers() -> None:
    """Public list/count methods route plain and identifier-filtered requests correctly."""
    user = _user()
    with (
        patch.object(
            TenantScopedEntity, "list_items", new=AsyncMock(return_value=[user])
        ) as parent_list,
        patch.object(
            TenantScopedEntity, "total_count", new=AsyncMock(return_value=1)
        ) as parent_count,
    ):
        assert await models.User.list_items(
            user_id="user-1", tenant_id="tenant-1", role="member"
        ) == [user]
        assert await models.User.total_count(tenant_id="tenant-1", role="member") == 1
    assert parent_list.await_args.kwargs["uid"] == "user-1"
    assert parent_list.await_args.kwargs["roles_in"] == "member"
    assert parent_count.await_args.kwargs["roles_in"] == "member"

    with (
        patch.object(
            models.User,
            "_list_items_with_identifier_filter",
            new=AsyncMock(return_value=[user]),
        ) as filtered_list,
        patch.object(
            models.User,
            "_total_count_with_identifier_filter",
            new=AsyncMock(return_value=1),
        ) as filtered_count,
    ):
        assert await models.User.list_items(identifier="ali") == [user]
        assert await models.User.total_count(identifier="ali") == 1
    filtered_list.assert_awaited_once()
    filtered_count.assert_awaited_once()


def test_user_queryset_filters_name_case_insensitively() -> None:
    """Admin user directory search matches name as a case-insensitive substring."""
    with patch.object(
        TenantScopedEntity,
        "get_queryset",
        return_value={"tenant_id": "tenant-1"},
    ):
        query = models.User.get_queryset(tenant_id="tenant-1", name="  Ada ")
        like_query = models.User.get_queryset(tenant_id="tenant-1", name_like="  Ada ")
    assert query["name"] == {"$regex": "Ada", "$options": "i"}
    assert like_query["name"] == {"$regex": "Ada", "$options": "i"}


def test_user_queryset_filters_by_workspace_ids_in() -> None:
    """Users can be restricted to members of resolved workspace uid sets."""
    with patch.object(
        TenantScopedEntity,
        "get_queryset",
        side_effect=lambda **_kwargs: {"tenant_id": "tenant-1"},
    ):
        query = models.User.get_queryset(
            tenant_id="tenant-1",
            workspace_ids_in=["ws-1", "ws-2"],
        )
        empty = models.User.get_queryset(tenant_id="tenant-1", workspace_ids_in=[])
    assert query["workspace_ids"] == {"$in": ["ws-1", "ws-2"]}
    assert empty["workspace_ids"] == {"$in": []}
