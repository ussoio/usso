"""User create/update audit logging."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi_mongo_base.audit.context import audit_actor_scope, get_audit_actor

from apps.identity.user import services


@pytest.mark.asyncio
async def test_record_user_created_uses_bound_admin_actor() -> None:
    admin = SimpleNamespace(
        uid="admin-1",
        user_id="admin-1",
        tenant_id="tenant-1",
        workspace_id=None,
        claims={"sub_type": "user"},
    )
    target = SimpleNamespace(tenant_id="tenant-1", uid="target-1")

    with (
        audit_actor_scope(admin),
        patch(
            "apps.identity.user.services.maybe_record_audit",
            new=AsyncMock(),
        ) as audit_mock,
    ):
        await services.record_user_created(target)  # type: ignore[arg-type]

    audit_mock.assert_awaited_once()
    assert audit_mock.await_args.kwargs["item"] is target


def test_self_registration_scope_binds_new_user() -> None:
    target = SimpleNamespace(tenant_id="tenant-1", uid="self-1")

    with services.self_registration_audit_scope(target):  # type: ignore[arg-type]
        actor = get_audit_actor()
        assert actor is not None
        assert actor.user_id == "self-1"
        assert actor.sub_type == "self_registration"

    assert get_audit_actor() is None


def test_bootstrap_scope_binds_system_actor() -> None:
    with services.bootstrap_audit_scope(tenant_id="tenant-1"):
        actor = get_audit_actor()
        assert actor is not None
        assert actor.tenant_id == "tenant-1"
        assert actor.sub_type == "bootstrap"
        assert actor.principal_id == "bootstrap"

    assert get_audit_actor() is None
