"""Focused unit coverage for user, identifier, and credential route handlers."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from apps.identity.auth.enums import AuthIdentifier, AuthSecret, LoginStatus
from apps.identity.user import routes, schemas
from server.exceptions import (
    AlreadyExistsError,
    BadRequestError,
    ForbiddenError,
    NotFoundError,
)


def _request() -> MagicMock:
    request = MagicMock()
    request.headers = {"origin": "https://app.example.com", "user-agent": "pytest"}
    request.url = SimpleNamespace(hostname="app.example.com")
    return request


def _caller() -> SimpleNamespace:
    return SimpleNamespace(
        uid="admin-1", user_id="admin-1", tenant_id="tenant-1", scopes=[]
    )


def _target(**overrides: object) -> SimpleNamespace:
    values = {
        "uid": "user-1",
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "roles": [],
        "meta_data": None,
        "is_deleted": False,
        "model_dump": MagicMock(return_value={"uid": "user-1"}),
        "save": AsyncMock(),
        "delete": AsyncMock(),
        "to_detailed_schema": AsyncMock(return_value="detailed"),
        "update_permissions_and_sessions": AsyncMock(),
        "get_identifiers": AsyncMock(return_value=[]),
        "get_credentials": AsyncMock(return_value=[]),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _identifier(
    *,
    uid: str = "identifier-1",
    user_id: str = "user-1",
    typ: AuthIdentifier = AuthIdentifier.EMAIL,
    value: str = "user@example.com",
) -> SimpleNamespace:
    data = {
        "uid": uid,
        "tenant_id": "tenant-1",
        "user_id": user_id,
        "type": typ,
        "identifier": value,
        "verified_at": None,
        "is_primary": False,
        "is_active": True,
        "searchable": True,
    }
    return SimpleNamespace(
        **data,
        model_dump=MagicMock(return_value=data.copy()),
        save=AsyncMock(),
        delete=AsyncMock(),
    )


def _credential(
    *,
    uid: str = "credential-1",
    user_id: str = "user-1",
    method: AuthSecret = AuthSecret.PASSWORD,
    credential_value: str = "test-value",
) -> SimpleNamespace:
    data = {
        "uid": uid,
        "tenant_id": "tenant-1",
        "user_id": user_id,
        "method": method,
        "secret": credential_value,
        "is_active": True,
        "expires_at": None,
    }
    return SimpleNamespace(
        **data,
        is_deleted=False,
        model_dump=MagicMock(return_value=data.copy()),
        save=AsyncMock(),
        delete=AsyncMock(),
    )


@contextmanager
def _configure_target_router(
    router: routes.UserRouter, target: SimpleNamespace | None = None
) -> Iterator[tuple[SimpleNamespace, SimpleNamespace]]:
    caller = _caller()
    target = target or _target()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=caller)),
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=SimpleNamespace(uid="tenant-1")),
        ),
        patch.object(router, "get_item", new=AsyncMock(return_value=target)),
        patch.object(router, "authorize", new=AsyncMock()),
    ):
        yield caller, target


@pytest.mark.asyncio
async def test_list_retrieve_and_delete_user_handlers() -> None:
    router = routes.UserRouter()
    request = _request()
    page = SimpleNamespace(items=[])
    list_items = AsyncMock(return_value=page)
    with (
        _configure_target_router(router) as (caller, target),
        patch.object(router, "_list_items", new=list_items),
        patch.object(
            routes.services,
            "attach_user_list_directory",
            new=AsyncMock(),
        ) as attach,
        patch.object(
            router.model, "hard_delete", new=AsyncMock(return_value=target)
        ) as hard_delete,
    ):
        assert (
            await router.list_items(
                request,
                offset=2,
                limit=4,
                identifier_type=AuthIdentifier.EMAIL,
                identifier="ada@example.com",
                role="admin",
                is_active=True,
                is_limited=False,
                name_like="Ada",
            )
            is page
        )
        assert await router.retrieve_item(request, "user-1") == "detailed"
        assert await router.delete_item(request, "user-1") == "detailed"
        list_items.assert_awaited_once()
        assert list_items.await_args.kwargs["name_like"] == "Ada"
        attach.assert_awaited_once_with(page.items, tenant_id="tenant-1")
        router.get_item.assert_has_awaits([
            call(uid="user-1", user_id=None, tenant_id="tenant-1"),
            call(uid="user-1", user_id=None, tenant_id="tenant-1"),
        ])
        router.authorize.assert_has_awaits([
            call(action="read", user=caller, filter_data={"uid": "user-1"}),
            call(action="delete", user=caller, filter_data={"uid": "user-1"}),
        ])
    hard_delete.assert_awaited_once_with(target)


@pytest.mark.asyncio
async def test_delete_item_rejects_self_delete() -> None:
    """Admin cannot hard-delete their own account via DELETE /users/{uid}."""
    from server.exceptions import BadRequestError

    router = routes.UserRouter()
    request = _request()
    caller = _target(uid="admin-1")
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=caller)),
        patch.object(router, "get_item", new=AsyncMock(return_value=caller)),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(router.model, "hard_delete", new=AsyncMock()) as hard_delete,
        pytest.raises(BadRequestError) as exc_info,
    ):
        await router.delete_item(request, "admin-1")
    assert exc_info.value.error_code == "cannot_delete_self"
    hard_delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_list_users_resolves_workspace_name_like_to_workspace_ids() -> None:
    """workspace_name_like looks up matching workspaces then filters members."""
    router = routes.UserRouter()
    request = _request()
    page = SimpleNamespace(items=[])
    list_items = AsyncMock(return_value=page)
    workspaces = [SimpleNamespace(uid="ws-acme"), SimpleNamespace(uid="ws-acme-2")]
    workspace_query = MagicMock()
    workspace_query.to_list = AsyncMock(return_value=workspaces)
    with (
        _configure_target_router(router) as (_caller, _target),
        patch.object(router, "_list_items", new=list_items),
        patch.object(
            routes.services,
            "attach_user_list_directory",
            new=AsyncMock(),
        ),
        patch(
            "apps.access_control.workspace.models.Workspace.get_query",
            return_value=workspace_query,
        ) as get_query,
    ):
        assert (
            await router.list_items(
                request,
                offset=0,
                limit=10,
                workspace_name_like="  Acme ",
            )
            is page
        )
    get_query.assert_called_once_with(tenant_id="tenant-1", name_like="Acme")
    assert list_items.await_args.kwargs["workspace_ids_in"] == ["ws-acme", "ws-acme-2"]


@pytest.mark.asyncio
async def test_create_user_assigns_roles_without_admin_action() -> None:
    router = routes.UserRouter()
    request = _request()
    caller = _caller()
    tenant = SimpleNamespace(uid="tenant-1")
    created = _target()
    authorize = AsyncMock()
    data = schemas.UserCreateSchema(
        name="Ada Lovelace",
        identifier="ada@example.com",
        roles=["member"],
        meta_data={"source": "admin"},
    )
    with (
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(router, "get_user", new=AsyncMock(return_value=caller)),
        patch.object(router, "authorize", new=authorize),
        patch.object(routes.services, "find_user", new=AsyncMock(return_value=None)),
        patch.object(
            routes.services, "create_user", new=AsyncMock(return_value=created)
        ) as create,
        patch.object(
            routes.services,
            "assert_assignable_tenant_roles",
            new=AsyncMock(),
        ) as assert_roles,
    ):
        assert await router.create_item(request, data) == "detailed"
    assert authorize.await_count == 1
    assert authorize.await_args.kwargs["action"] == "create"
    assert_roles.assert_awaited_once_with(
        tenant_id="tenant-1",
        user_data=caller,
        role_names=["member"],
    )
    create.assert_awaited_once()
    assert created.roles == ["member"]
    assert created.name == "Ada Lovelace"
    assert created.is_active is True
    assert created.meta_data == {"source": "admin"}
    created.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_user_writes_officer_fields_to_profile() -> None:
    router = routes.UserRouter()
    request = _request()
    created = _target()
    data = schemas.UserCreateSchema(
        name="علی رضایی",
        first_name="علی",
        last_name="رضایی",
        identifier="09120000000",
        identifier_type=AuthIdentifier.PHONE,
    )
    with (
        patch.object(
            router, "get_tenant", new=AsyncMock(return_value=SimpleNamespace(uid="t1"))
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=_caller())),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(routes.services, "find_user", new=AsyncMock(return_value=None)),
        patch.object(
            routes.services, "create_user", new=AsyncMock(return_value=created)
        ),
        patch.object(
            routes.services, "assert_assignable_tenant_roles", new=AsyncMock()
        ),
        patch.object(
            routes.services, "upsert_admin_profile", new=AsyncMock()
        ) as upsert_profile,
    ):
        assert await router.create_item(request, data) == "detailed"
    upsert_profile.assert_awaited_once_with(
        user=created,
        first_name="علی",
        last_name="رضایی",
    )


@pytest.mark.asyncio
async def test_create_user_writes_birth_date_to_kyc() -> None:
    """Admin birth_date is stored on KYC, not on the User document."""
    from datetime import date

    router = routes.UserRouter()
    created = _target()
    data = schemas.UserCreateSchema(
        name="علی رضایی",
        national_id="0012345678",
        birth_date=date(2001, 8, 29),
        identifier="09120000000",
        identifier_type=AuthIdentifier.PHONE,
    )
    with (
        patch.object(
            router, "get_tenant", new=AsyncMock(return_value=SimpleNamespace(uid="t1"))
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=_caller())),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(routes.services, "find_user", new=AsyncMock(return_value=None)),
        patch.object(
            routes.services, "create_user", new=AsyncMock(return_value=created)
        ),
        patch.object(
            routes.services, "assert_assignable_tenant_roles", new=AsyncMock()
        ),
        patch.object(routes.services, "upsert_admin_profile", new=AsyncMock()),
        patch.object(
            routes.models,
            "UserIdentifier",
            return_value=SimpleNamespace(save=AsyncMock()),
        ),
        patch.object(
            routes.services, "upsert_admin_kyc", new=AsyncMock()
        ) as upsert_kyc,
    ):
        assert await router.create_item(_request(), data) == "detailed"
    upsert_kyc.assert_awaited_once_with(user=created, birth_date=date(2001, 8, 29))


@pytest.mark.asyncio
@pytest.mark.parametrize("existing", [True, False])
async def test_create_user_reports_existing_or_registration_failure(
    existing: bool,
) -> None:
    router = routes.UserRouter()
    request = _request()
    data = schemas.UserCreateSchema(identifier="ada@example.com")
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=SimpleNamespace(uid="tenant-1")),
        ),
        patch.object(router, "get_user", new=AsyncMock(return_value=_caller())),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(
            routes.services,
            "find_user",
            new=AsyncMock(return_value=_target() if existing else None),
        ),
        patch.object(routes.services, "create_user", new=AsyncMock(return_value=None)),
        patch.object(
            routes.services, "assert_assignable_tenant_roles", new=AsyncMock()
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await router.create_item(request, data)
    assert exc.value.error_code == (
        "user_already_exists" if existing else "registration_failed"
    )


@pytest.mark.asyncio
async def test_update_user_propagates_global_and_workspace_permissions() -> None:
    router = routes.UserRouter()
    request = _request()
    updated = _target(workspace_ids=["ws-personal"])
    data = schemas.UserUpdateSchema(
        roles=["member"], workspace_roles={"ws-1": ["owner"]}
    )
    with (
        _configure_target_router(router) as (caller, _),
        patch.object(
            router.model, "update_item", new=AsyncMock(return_value=updated)
        ) as update_item,
        patch.object(
            routes.services, "assert_assignable_tenant_roles", new=AsyncMock()
        ) as assert_roles,
    ):
        assert await router.update_item(request, "user-1", data) == "detailed"
        router.authorize.assert_awaited_once_with(
            action="update", user=caller, filter_data={"uid": "user-1"}
        )
        assert_roles.assert_awaited_once_with(
            tenant_id="tenant-1",
            user_data=caller,
            role_names=["member"],
        )
    update_data = update_item.await_args.args[1]
    assert update_data == {"roles": ["member"], "workspace_roles": {"ws-1": ["owner"]}}
    updated.update_permissions_and_sessions.assert_has_awaits([
        call(workspace_id=None),
        call(workspace_id="ws-personal"),
        call(workspace_id="ws-1"),
    ])


@pytest.mark.asyncio
async def test_update_user_writes_officer_fields_to_profile() -> None:
    router = routes.UserRouter()
    updated = _target()
    data = schemas.UserUpdateSchema(
        first_name="علی",
        last_name="رضایی",
    )
    with (
        _configure_target_router(router),
        patch.object(
            router.model, "update_item", new=AsyncMock(return_value=updated)
        ) as update_item,
        patch.object(
            routes.services, "upsert_admin_profile", new=AsyncMock()
        ) as upsert_profile,
    ):
        assert await router.update_item(_request(), "user-1", data) == "detailed"
    assert "first_name" not in update_item.await_args.args[1]
    upsert_profile.assert_awaited_once_with(
        user=updated,
        first_name="علی",
        last_name="رضایی",
    )


@pytest.mark.asyncio
async def test_update_user_writes_birth_date_to_kyc() -> None:
    """Admin birth_date updates are routed to KYC, not User.update_item."""
    from datetime import date

    router = routes.UserRouter()
    updated = _target()
    data = schemas.UserUpdateSchema(birth_date=date(2001, 8, 29))
    with (
        _configure_target_router(router),
        patch.object(
            router.model, "update_item", new=AsyncMock(return_value=updated)
        ) as update_item,
        patch.object(
            routes.services, "upsert_admin_kyc", new=AsyncMock()
        ) as upsert_kyc,
    ):
        assert await router.update_item(_request(), "user-1", data) == "detailed"
    assert "birth_date" not in update_item.await_args.args[1]
    upsert_kyc.assert_awaited_once_with(user=updated, birth_date=date(2001, 8, 29))


@pytest.mark.asyncio
async def test_update_user_roles_refresh_existing_workspace_sessions() -> None:
    """Tenant role changes must refresh personal/org workspace-bound sessions."""
    router = routes.UserRouter()
    updated = _target(workspace_ids=["ws-personal", "ws-org"])
    with (
        _configure_target_router(router),
        patch.object(router.model, "update_item", new=AsyncMock(return_value=updated)),
        patch.object(
            routes.services, "assert_assignable_tenant_roles", new=AsyncMock()
        ),
    ):
        await router.update_item(
            _request(), "user-1", schemas.UserUpdateSchema(roles=["admin"])
        )
    updated.update_permissions_and_sessions.assert_has_awaits([
        call(workspace_id=None),
        call(workspace_id="ws-personal"),
        call(workspace_id="ws-org"),
    ])


@pytest.mark.asyncio
async def test_update_user_without_permission_fields_skips_sessions() -> None:
    router = routes.UserRouter()
    updated = _target()
    with (
        _configure_target_router(router),
        patch.object(router.model, "update_item", new=AsyncMock(return_value=updated)),
    ):
        assert (
            await router.update_item(
                _request(), "user-1", schemas.UserUpdateSchema(name="Ada")
            )
            == "detailed"
        )
    updated.update_permissions_and_sessions.assert_not_awaited()


@pytest.mark.asyncio
async def test_empty_workspace_roles_still_refreshes_global_permissions() -> None:
    router = routes.UserRouter()
    updated = _target()
    with (
        _configure_target_router(router),
        patch.object(router.model, "update_item", new=AsyncMock(return_value=updated)),
    ):
        await router.update_item(
            _request(), "user-1", schemas.UserUpdateSchema(workspace_roles={})
        )
    updated.update_permissions_and_sessions.assert_awaited_once_with(workspace_id=None)


@pytest.mark.asyncio
async def test_impersonation_handlers_delegate_prepare_otp_and_issue() -> None:
    router = routes.UserRouter()
    request = _request()
    caller = _caller()
    target = _target()
    tenant = SimpleNamespace(uid="tenant-1")
    prepare = AsyncMock(return_value=(caller, target, tenant))
    issue = AsyncMock(return_value="response")
    otp_request = schemas.ImpersonateOTPRequest()
    verify_request = schemas.ImpersonateOTPVerifyRequest(otp="123456")
    with (
        patch.object(router, "_prepare_impersonation", new=prepare),
        patch.object(router, "_issue_impersonation_response", new=issue),
        patch.object(
            routes.impersonation,
            "send_impersonation_otp",
            new=AsyncMock(return_value={"sent": True}),
        ) as send,
        patch.object(
            routes.impersonation, "verify_impersonation_otp", new=AsyncMock()
        ) as verify,
    ):
        assert await router.impersonate_user(request, "user-1") == "response"
        assert await router.impersonate_otp_challenge(
            request, "user-1", otp_request
        ) == {"sent": True}
        assert (
            await router.impersonate_otp_verify(request, "user-1", verify_request)
            == "response"
        )
    send.assert_awaited_once()
    verify.assert_awaited_once_with(
        user=target,
        tenant=tenant,
        requested_by="admin-1",
        mode=verify_request.mode,
        otp="123456",
    )
    assert issue.await_count == 2


@pytest.mark.asyncio
async def test_prepare_and_issue_impersonation_session() -> None:
    router = routes.UserRouter()
    request = _request()
    tenant = SimpleNamespace(
        uid="tenant-1",
        refresh_auth=MagicMock(return_value=None),
    )
    session = object()
    payloads = object()
    with (
        _configure_target_router(router) as (caller, target),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes.impersonation,
            "create_impersonation_session",
            new=AsyncMock(return_value=session),
        ) as create_session,
        patch.object(
            routes.impersonation,
            "create_impersonation_tokens",
            return_value=payloads,
        ),
        patch.object(routes, "build_login_response", return_value="response") as build,
    ):
        assert await router._prepare_impersonation(request, "user-1") == (
            caller,
            target,
            tenant,
        )
        result = await router._issue_impersonation_response(
            request=request,
            tenant=tenant,
            caller_uid="admin-1",
            target=target,
            mode=schemas.ImpersonationMode.READONLY,
            consent="admin",
        )
    assert result == "response"
    create_session.assert_awaited_once()
    build.assert_called_once_with(
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=LoginStatus.COMPLETED,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("caller", "uid", "target", "error_type", "error_code"),
    [
        (None, "user-1", _target(), ForbiddenError, "authentication_required"),
        (_caller(), "admin-1", _target(), BadRequestError, "cannot_impersonate_self"),
        (
            _caller(),
            "user-1",
            _target(is_deleted=True),
            NotFoundError,
            "user_not_found",
        ),
    ],
)
async def test_prepare_impersonation_rejects_invalid_targets(
    caller: object, uid: str, target: object, error_type: type, error_code: str
) -> None:
    router = routes.UserRouter()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=caller)),
        patch.object(router, "get_item", new=AsyncMock(return_value=target)),
        pytest.raises(error_type) as exc,
    ):
        await router._prepare_impersonation(_request(), uid)
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
async def test_list_identifiers_paginates_and_authorizes() -> None:
    identifiers = [_identifier(uid=f"identifier-{index}") for index in range(3)]
    router = routes.UserRouter()
    with _configure_target_router(
        router, _target(get_identifiers=AsyncMock(return_value=identifiers))
    ) as (caller, target):
        page = await router.list_identifiers(_request(), "user-1", offset=1, limit=1)
        assert page.total == 3
        assert [item.uid for item in page.items] == ["identifier-1"]
        router.authorize.assert_awaited_once_with(
            action="read", user=caller, filter_data={"uid": "user-1"}
        )
    target.get_identifiers.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_identifier_rejects_duplicate() -> None:
    router = routes.UserRouter()
    with (
        _configure_target_router(router),
        patch.object(
            routes.models.UserIdentifier,
            "find_one",
            new=AsyncMock(return_value=object()),
        ),
        pytest.raises(AlreadyExistsError),
    ):
        await router.create_identifier(
            _request(),
            "user-1",
            schemas.UserIdentifierCreateSchema(
                type=AuthIdentifier.EMAIL, identifier="user@example.com"
            ),
        )


@pytest.mark.asyncio
async def test_create_identifier_saves_and_sends_verification_otp() -> None:
    router = routes.UserRouter()
    request = _request()
    caller = _caller()
    caller.uid = "user-1"
    caller.user_id = "user-1"
    target = _target()
    created = _identifier()
    identifier_cls = MagicMock(return_value=created)
    identifier_cls.find_one = AsyncMock(return_value=None)
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=caller)),
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=SimpleNamespace(uid="tenant-1")),
        ),
        patch.object(router, "get_item", new=AsyncMock(return_value=target)),
        patch.object(router, "authorize", new=AsyncMock()),
        patch.object(routes.models, "UserIdentifier", identifier_cls),
        patch.object(routes.services, "needs_verification", return_value=True),
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value="email",
        ),
        patch(
            "apps.identity.auth.services.create_otp",
            new=AsyncMock(return_value="123456"),
        ) as create_otp,
    ):
        result = await router.create_identifier(
            request,
            "user-1",
            schemas.UserIdentifierCreateSchema(
                type=AuthIdentifier.EMAIL,
                identifier="user@example.com",
                is_primary=True,
            ),
        )
    assert result.identifier == "user@example.com"
    created.save.assert_awaited_once()
    create_otp.assert_awaited_once()
    assert create_otp.await_args.kwargs["origin"] == "app.example.com"


@pytest.mark.asyncio
async def test_update_identifier_updates_only_set_fields() -> None:
    router = routes.UserRouter()
    identifier = _identifier()
    with (
        _configure_target_router(router),
        patch.object(
            routes.models.UserIdentifier,
            "get_by_uid",
            new=AsyncMock(return_value=identifier),
        ),
    ):
        result = await router.update_identifier(
            _request(),
            "user-1",
            "identifier-1",
            schemas.UserIdentifierUpdateSchema(is_primary=True),
        )
    assert result.uid == "identifier-1"
    assert identifier.is_primary is True
    identifier.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_identifier_not_found_and_last_identifier_errors() -> None:
    router = routes.UserRouter()
    with _configure_target_router(
        router, _target(get_identifiers=AsyncMock(return_value=[object()]))
    ) as (_, target):
        with (
            patch.object(
                routes.models.UserIdentifier,
                "get_by_uid",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(NotFoundError),
        ):
            await router.update_identifier(
                _request(),
                "user-1",
                "missing",
                schemas.UserIdentifierUpdateSchema(is_active=False),
            )
        identifier = _identifier()
        with (
            patch.object(
                routes.models.UserIdentifier,
                "get_by_uid",
                new=AsyncMock(return_value=identifier),
            ),
            pytest.raises(BadRequestError) as exc,
        ):
            await router.delete_identifier(_request(), "user-1", "identifier-1")
        assert exc.value.error_code == "cannot_delete_last_identifier"
    target.get_identifiers.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_identifier_deletes_when_another_identifier_exists() -> None:
    identifier = _identifier()
    router = routes.UserRouter()
    with (
        _configure_target_router(
            router,
            _target(get_identifiers=AsyncMock(return_value=[identifier, object()])),
        ),
        patch.object(
            routes.models.UserIdentifier,
            "get_by_uid",
            new=AsyncMock(return_value=identifier),
        ),
    ):
        assert (
            await router.delete_identifier(_request(), "user-1", "identifier-1")
            is identifier
        )
    identifier.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_identifier_rejects_invalid_code_then_marks_valid() -> None:
    identifier = _identifier()
    target = _target()
    router = routes.UserRouter()
    with _configure_target_router(router, target):
        with (
            patch.object(
                routes.models.UserIdentifier,
                "get_by_uid",
                new=AsyncMock(return_value=identifier),
            ),
            patch.object(
                routes.models.Credential, "find_one", new=AsyncMock(return_value=None)
            ),
            pytest.raises(BadRequestError) as exc,
        ):
            await router.verify_identifier(
                _request(),
                "user-1",
                "identifier-1",
                schemas.VerificationRequestSchema(code="bad"),
            )
        assert exc.value.error_code == "invalid_verification_code"

        verification = _credential(method=AuthSecret.EMAIL_OTP)
        with (
            patch.object(
                routes.models.UserIdentifier,
                "get_by_uid",
                new=AsyncMock(return_value=identifier),
            ),
            patch.object(
                routes.models.Credential,
                "find_one",
                new=AsyncMock(return_value=verification),
            ),
        ):
            result = await router.verify_identifier(
                _request(),
                "user-1",
                "identifier-1",
                schemas.VerificationRequestSchema(code="123456"),
            )
    assert result.uid == "identifier-1"
    assert isinstance(identifier.verified_at, datetime)
    identifier.save.assert_awaited_once()
    verification.delete.assert_awaited_once()
    target.update_permissions_and_sessions.assert_awaited_once()


@pytest.mark.asyncio
async def test_resend_verification_resolves_channel_and_origin() -> None:
    router = routes.UserRouter()
    identifier = _identifier(typ=AuthIdentifier.PHONE, value="+989121234567")
    with (
        _configure_target_router(router),
        patch.object(
            routes.models.UserIdentifier,
            "get_by_uid",
            new=AsyncMock(return_value=identifier),
        ),
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value="sms",
        ) as resolve,
        patch(
            "apps.identity.auth.services.create_otp",
            new=AsyncMock(return_value="654321"),
        ) as create_otp,
    ):
        assert await router.resend_verification(
            _request(), "user-1", "identifier-1"
        ) == {"otp": "654321"}
        resolve.assert_called_once_with(
            typ="sms", tenant=router.get_tenant.return_value
        )
    assert create_otp.await_args.kwargs["origin"] == "app.example.com"


@pytest.mark.asyncio
async def test_identifier_handlers_reject_missing_identifier() -> None:
    router = routes.UserRouter()
    with (
        _configure_target_router(router),
        patch.object(
            routes.models.UserIdentifier,
            "get_by_uid",
            new=AsyncMock(return_value=None),
        ),
    ):
        with pytest.raises(NotFoundError):
            await router.delete_identifier(_request(), "user-1", "missing")
        with pytest.raises(NotFoundError):
            await router.verify_identifier(
                _request(),
                "user-1",
                "missing",
                schemas.VerificationRequestSchema(code="123456"),
            )
        with pytest.raises(NotFoundError):
            await router.resend_verification(_request(), "user-1", "missing")


@pytest.mark.asyncio
async def test_list_credentials_paginates_without_exposing_secret() -> None:
    credentials = [_credential(uid=f"credential-{index}") for index in range(3)]
    router = routes.UserRouter()
    with _configure_target_router(
        router, _target(get_credentials=AsyncMock(return_value=credentials))
    ):
        page = await router.list_credentials(_request(), "user-1", offset=1, limit=1)
    assert page.total == 3
    assert page.items[0].uid == "credential-1"


@pytest.mark.asyncio
async def test_create_and_update_password_credential_hash_secrets() -> None:
    router = routes.UserRouter()
    created = _credential(credential_value="hashed")
    credential_cls = MagicMock(return_value=created)
    credential_cls.get_by_uid = AsyncMock(return_value=created)
    with (
        _configure_target_router(router),
        patch.object(routes.models, "Credential", credential_cls),
        patch.object(routes, "require_secure_token") as require,
        patch(
            "utils.hasher.PasswordHasherService.hash_password",
            side_effect=lambda value: f"hashed-{value}",
        ) as hash_password,
    ):
        response = await router.create_credential(
            _request(),
            "user-1",
            schemas.CredentialCreateSchema(
                method=AuthSecret.PASSWORD, secret="new-secret"
            ),
        )
        updated = await router.update_credential(
            _request(),
            "user-1",
            "credential-1",
            schemas.CredentialUpdateSchema(secret="changed"),
        )
    assert response.uid == "credential-1"
    assert updated.uid == "credential-1"
    assert credential_cls.call_args.kwargs["secret"] == "hashed-new-secret"
    assert created.secret == "hashed-changed"
    assert hash_password.call_count == 2
    assert require.call_count == 2
    assert created.save.await_count == 2


@pytest.mark.asyncio
async def test_delete_credential_checks_ownership_and_deletes() -> None:
    router = routes.UserRouter()
    with _configure_target_router(router):
        with (
            patch.object(routes, "require_secure_token"),
            patch.object(
                routes.models.Credential,
                "get_by_uid",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(NotFoundError),
        ):
            await router.delete_credential(_request(), "user-1", "missing")
        credential = _credential()
        with (
            patch.object(routes, "require_secure_token"),
            patch.object(
                routes.models.Credential,
                "get_by_uid",
                new=AsyncMock(return_value=credential),
            ),
        ):
            assert (
                await router.delete_credential(_request(), "user-1", "credential-1")
                is credential
            )
    credential.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_and_reset_credential_reject_missing_credential() -> None:
    router = routes.UserRouter()
    with (
        _configure_target_router(router),
        patch.object(routes, "require_secure_token"),
        patch.object(
            routes.models.Credential, "get_by_uid", new=AsyncMock(return_value=None)
        ),
    ):
        with pytest.raises(NotFoundError):
            await router.update_credential(
                _request(),
                "user-1",
                "missing",
                schemas.CredentialUpdateSchema(is_active=False),
            )
        with pytest.raises(NotFoundError):
            await router.reset_credential(_request(), "user-1", "missing")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "expected"),
    [
        (AuthSecret.PASSWORD, "error"),
        (AuthSecret.TOTP, "totp"),
        (AuthSecret.WEBAUTHN, "deleted"),
        (AuthSecret.EMAIL_OTP, "expired"),
    ],
)
async def test_reset_credential_handles_each_method(
    method: AuthSecret, expected: str
) -> None:
    router = routes.UserRouter()
    credential = _credential(method=method)
    with (
        _configure_target_router(router) as (_, target),
        patch.object(routes, "require_secure_token"),
        patch.object(
            routes.models.Credential,
            "get_by_uid",
            new=AsyncMock(return_value=credential),
        ),
        patch.object(
            routes.credential_services,
            "register_random_totp_challenge",
            new=AsyncMock(return_value={"secret": "totp"}),
        ) as register,
    ):
        if expected == "error":
            with pytest.raises(BadRequestError) as exc:
                await router.reset_credential(_request(), "user-1", "credential-1")
            assert exc.value.error_code == "use_password_endpoint"
        else:
            result = await router.reset_credential(_request(), "user-1", "credential-1")
            if expected == "totp":
                assert result == {"secret": "totp"}
                register.assert_awaited_once()
            else:
                assert result["message"].startswith("Credential reset")
    if expected in {"totp", "deleted"}:
        credential.delete.assert_awaited_once()
    if expected == "expired":
        assert credential.is_deleted is True
        credential.save.assert_awaited_once()
    assert target.uid == "user-1"


@pytest.mark.asyncio
async def test_identifier_router_create_adds_authenticated_scope() -> None:
    router = routes.IdentifierRouter()
    created = object()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=_caller())),
        patch.object(
            routes.models.UserIdentifier,
            "create_item",
            new=AsyncMock(return_value=created),
        ) as create,
    ):
        assert (
            await router.create_item(
                _request(),
                schemas.UserIdentifierCreateSchema(
                    type=AuthIdentifier.EMAIL, identifier="user@example.com"
                ),
            )
            is created
        )
    payload = create.await_args.args[0]
    assert payload["user_id"] == "admin-1"
    assert payload["tenant_id"] == "tenant-1"


@pytest.mark.asyncio
async def test_credential_router_basic_and_challenge_handlers() -> None:
    router = routes.CredentialRouter()
    request = _request()
    user = _caller()
    tenant = SimpleNamespace(uid="tenant-1")
    created = object()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(router, "_list_items", new=AsyncMock(return_value="page")),
        patch.object(
            routes.models.Credential,
            "create_item",
            new=AsyncMock(return_value=created),
        ) as create,
        patch.object(
            routes.credential_services,
            "register_passkey",
            new=AsyncMock(return_value={"challenge": "passkey"}),
        ) as passkey_challenge,
        patch.object(
            routes.credential_services,
            "register_random_totp_challenge",
            new=AsyncMock(return_value={"challenge": "totp"}),
        ) as totp_challenge,
        patch.object(routes, "require_secure_token") as require,
    ):
        assert await router.list_items(request, 1, 2) == "page"
        assert (
            await router.create_item(
                request,
                schemas.CredentialCreateSchema(
                    method=AuthSecret.EMAIL_OTP, secret="123456"
                ),
            )
            is created
        )
        assert await router.get_passkey_challenge(request) == {"challenge": "passkey"}
        assert await router.get_totp_challenge(request) == {"challenge": "totp"}
    assert create.await_args.args[0]["tenant_id"] == "tenant-1"
    passkey_challenge.assert_awaited_once_with(
        tenant, user, "app.example.com", origin="https://app.example.com"
    )
    totp_challenge.assert_awaited_once_with(tenant, user, "app.example.com")
    require.assert_called_once_with(request=request, tenant=tenant, user_id="admin-1")


@pytest.mark.asyncio
async def test_credential_router_registration_success_and_failure() -> None:
    router = routes.CredentialRouter()
    request = _request()
    user = _caller()
    tenant = SimpleNamespace(uid="tenant-1")
    assertion = MagicMock()
    assertion.model_dump.return_value = {"id": "passkey-1"}
    response = _credential(method=AuthSecret.WEBAUTHN)
    totp = _credential(method=AuthSecret.TOTP)
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.models.User,
            "get_item",
            new=AsyncMock(return_value=_target(uid="admin-1")),
        ),
        patch.object(
            routes.credential_services,
            "verify_registration_passkey",
            new=AsyncMock(side_effect=[response, None]),
        ),
        patch.object(
            routes.credential_services,
            "verify_totp_challenge",
            new=AsyncMock(return_value=totp),
        ) as verify_totp,
        patch.object(routes, "require_secure_token"),
    ):
        passkey_result = await router.create_passkey_credential(request, assertion)
        assert passkey_result.uid == "credential-1"
        with pytest.raises(BadRequestError) as exc:
            await router.create_passkey_credential(request, assertion)
        assert exc.value.error_code == "passkey_registration_failed"
        totp_result = await router.create_totp_credential(
            request,
            schemas.TOTPCreateSchema(secret="123456"),
        )
    assert totp_result.uid == "credential-1"
    verify_totp.assert_awaited_once()
