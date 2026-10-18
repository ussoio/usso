"""An editor may only change users whose access they fully hold."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from apps.identity.user import services
from server.exceptions import ForbiddenError


def _actor(*scopes: str, uid: str = "admin-1") -> SimpleNamespace:
    return SimpleNamespace(uid=uid, user_id=uid, tenant_id="t1", scopes=list(scopes))


def _target(*scopes: str, uid: str = "user-1") -> SimpleNamespace:
    return SimpleNamespace(uid=uid, get_scopes=AsyncMock(return_value=list(scopes)))


@pytest.mark.asyncio
async def test_lower_editor_cannot_touch_higher_user() -> None:
    actor = _actor("read:sso/usso/user", "update:sso/usso/user")
    superadmin = _target("*:sso/usso/*")
    with pytest.raises(ForbiddenError) as exc:
        await services.assert_manageable_user(actor=actor, target=superadmin)
    assert exc.value.error_code == "target_user_privileged"


@pytest.mark.asyncio
async def test_editor_covering_all_target_scopes_may_edit() -> None:
    actor = _actor("*:sso/usso/*")
    await services.assert_manageable_user(
        actor=actor, target=_target("read:sso/usso/user")
    )
    await services.assert_manageable_user(actor=actor, target=_target("*:sso/usso/*"))


@pytest.mark.asyncio
async def test_self_edit_is_not_blocked() -> None:
    actor = _actor("read:sso/usso/user", uid="same")
    await services.assert_manageable_user(
        actor=actor, target=_target("*:sso/usso/*", uid="same")
    )


@pytest.mark.asyncio
async def test_granting_scopes_beyond_own_is_blocked() -> None:
    actor = _actor("update:sso/usso/user")
    with pytest.raises(ForbiddenError) as exc:
        await services.assert_manageable_user(
            actor=actor, target=_target(), new_scopes=["*:sso/usso/*"]
        )
    assert exc.value.error_code == "scope_insufficient"
