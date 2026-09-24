"""Focused route coverage for KYC endpoints."""

from datetime import date
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.responses import RedirectResponse
from usso.exceptions import PermissionDenied

from apps.identity.kyc import routes
from apps.identity.kyc.schemas import KYCCreateSchema, KYCStatus
from server.exceptions import BadRequestError, NotFoundError, UnauthorizedError


def _kyc_data() -> KYCCreateSchema:
    return KYCCreateSchema.model_construct(
        national_code="0012345678",
        birth_date=date(1991, 3, 21),
        return_url="https://app.test/done",
    )


def _tenant(*, access: object = None, temporary: object = None) -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        get_auth=MagicMock(return_value=MagicMock(return_value=access)),
        temporary_auth=MagicMock(return_value=temporary),
        access_auth=MagicMock(return_value=access),
    )


@pytest.mark.asyncio
async def test_create_kyc_requires_access_or_temporary_payload() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.create_kyc(MagicMock(), _kyc_data())
    assert exc.value.error_code == "unauthorized"


@pytest.mark.asyncio
async def test_create_kyc_requires_registered_phone() -> None:
    payload = SimpleNamespace(sub="u1", user_id="u1", tenant_id="tenant-1")
    tenant = _tenant(access=payload)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "get_user_phone", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.create_kyc(MagicMock(), _kyc_data())
    assert exc.value.error_code == "phone_not_found"


@pytest.mark.asyncio
async def test_create_kyc_requires_phone_verification() -> None:
    payload = SimpleNamespace(sub="u1", user_id="u1", tenant_id="tenant-1")
    tenant = _tenant(temporary=payload)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "get_user_phone", new=AsyncMock(return_value="09120000000")
        ),
        patch.object(routes, "verify_phone", new=AsyncMock(return_value=False)),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.create_kyc(MagicMock(), _kyc_data())
    assert exc.value.error_code == "phone_not_verified"


@pytest.mark.asyncio
async def test_create_kyc_saves_activates_and_authenticates() -> None:
    payload = SimpleNamespace(sub="u1", user_id="u1", tenant_id="tenant-1")
    tenant = _tenant(temporary=payload)
    request = MagicMock()
    saved_kyc = SimpleNamespace(uid="kyc-1")
    kyc_instance = SimpleNamespace(save=AsyncMock(return_value=saved_kyc))
    kyc_cls = MagicMock(return_value=kyc_instance)
    user = SimpleNamespace(uid="u1", tenant_id="tenant-1")
    kyc_cls.get_item = AsyncMock()
    response = object()

    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "get_user_phone", new=AsyncMock(return_value="09120000000")
        ),
        patch.object(routes, "verify_phone", new=AsyncMock(return_value=True)),
        patch.object(
            routes.services,
            "verify_civil",
            new=AsyncMock(return_value={"matched": True}),
        ),
        patch.object(routes, "KYC", kyc_cls),
        patch.object(routes.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            routes.services,
            "resolve_user_for_national_code",
            new=AsyncMock(return_value=user),
        ) as resolve,
        patch.object(routes, "activate_user", new=AsyncMock()) as activate,
        patch.object(
            routes, "authenticate_user", new=AsyncMock(return_value=response)
        ) as authenticate,
    ):
        result = await routes.create_kyc(request, _kyc_data())

    assert result is response
    kyc_instance.save.assert_awaited_once()
    resolve.assert_awaited_once()
    activate.assert_awaited_once_with(saved_kyc, user)
    authenticate.assert_awaited_once_with(saved_kyc, request, user, payload, tenant)


def _query(result: object) -> MagicMock:
    query = MagicMock()
    query.sort.return_value = query
    query.first_or_none = AsyncMock(return_value=result)
    return query


@pytest.mark.asyncio
async def test_get_user_kyc_owner_path_returns_latest_record() -> None:
    user = SimpleNamespace(uid="u1", scopes=[])
    tenant = _tenant(access=user)
    found = object()
    query = _query(found)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes.authorization, "owner_authorization", return_value=True),
        patch.object(routes.KYC, "find", return_value=query) as find,
    ):
        result = await routes.get_user_kyc(MagicMock(), "u1")
    assert result is found
    find.assert_called_once_with({"user_id": "u1", "tenant_id": "tenant-1"})


@pytest.mark.asyncio
async def test_get_user_kyc_denies_missing_read_scope() -> None:
    user = SimpleNamespace(uid="viewer", scopes=[])
    tenant = _tenant(access=user)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes.authorization, "owner_authorization", return_value=False),
        patch.object(routes.authorization, "check_access", return_value=False),
        pytest.raises(PermissionDenied),
    ):
        await routes.get_user_kyc(MagicMock(), "u1")


@pytest.mark.asyncio
async def test_get_user_kyc_authorized_reader_returns_record() -> None:
    user = SimpleNamespace(uid="viewer", scopes=["read:/kyc"])
    tenant = _tenant(access=user)
    found = object()
    query = _query(found)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes.authorization, "owner_authorization", return_value=False),
        patch.object(routes.authorization, "check_access", return_value=True),
        patch.object(routes.KYC, "find", return_value=query),
    ):
        assert await routes.get_user_kyc(MagicMock(), "u1") is found


@pytest.mark.asyncio
async def test_callback_kyc_handles_missing_and_non_pending_records() -> None:
    payload = SimpleNamespace(tenant_id="tenant-1", sub="u1")
    tenant = _tenant(temporary=payload)
    get_tenant = AsyncMock(return_value=tenant)
    with (
        patch.object(routes, "get_request_tenant", new=get_tenant),
        patch.object(routes.KYC, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(NotFoundError),
    ):
        await routes.callback_kyc(MagicMock(), "missing")

    record = SimpleNamespace(status=KYCStatus.APPROVED)
    with (
        patch.object(routes, "get_request_tenant", new=get_tenant),
        patch.object(routes.KYC, "get_item", new=AsyncMock(return_value=record)),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.callback_kyc(MagicMock(), "kyc-1")
    assert exc.value.error_code == "kyc_not_pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verified", "expected_status"),
    [(False, KYCStatus.REJECTED), (True, KYCStatus.APPROVED)],
)
async def test_callback_kyc_updates_status_and_redirects(
    verified: bool, expected_status: KYCStatus
) -> None:
    payload = SimpleNamespace(tenant_id="tenant-1", sub="u1")
    tenant = _tenant(temporary=payload)
    request = MagicMock()
    record = SimpleNamespace(
        status=KYCStatus.PENDING,
        kyc_id="remote-1",
        return_url="https://app.test/done",
        user_id="u1",
        tenant_id="tenant-1",
        save=AsyncMock(),
    )
    user = SimpleNamespace(uid="u1")
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes.KYC, "get_item", new=AsyncMock(return_value=record)),
        patch.object(routes, "verify_kyc", new=AsyncMock(return_value=verified)),
        patch.object(
            routes.User, "get_item", new=AsyncMock(return_value=user)
        ) as get_user,
        patch.object(routes, "activate_user", new=AsyncMock()) as activate,
        patch.object(routes, "authenticate_user", new=AsyncMock()) as authenticate,
    ):
        response = await routes.callback_kyc(request, "kyc-1")

    assert isinstance(response, RedirectResponse)
    assert response.headers["location"] == "https://app.test/done"
    assert record.status == expected_status
    record.save.assert_awaited_once()
    if verified:
        get_user.assert_awaited_once()
        activate.assert_awaited_once_with(record, user)
        authenticate.assert_awaited_once_with(record, request, user, payload, tenant)
    else:
        get_user.assert_not_awaited()
