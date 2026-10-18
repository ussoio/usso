"""Admin-entered national ID + birth date pulls and keeps civil-registry data."""

from datetime import date
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from apps.identity.kyc import services as kyc_services
from apps.identity.user import services
from server.exceptions import BadRequestError, ServiceUnavailableError

CIVIL = {"firstName": "علی", "lastName": "احمدی", "fatherName": "رضا"}


def _patches(existing: object) -> tuple:
    user = SimpleNamespace(uid="u1", tenant_id="t1", name="موجود", save=AsyncMock())
    return user, (
        patch.object(
            services.UserIdentifier,
            "find_one",
            new=AsyncMock(return_value=SimpleNamespace(identifier="0012345678")),
        ),
        patch.object(services.KYC, "find_one", new=AsyncMock(return_value=existing)),
    )


@pytest.mark.asyncio
async def test_admin_kyc_stores_civil_data_and_time() -> None:
    existing = SimpleNamespace(
        civil_data=None, civil_verified_at=None, save=AsyncMock()
    )
    user, (p1, p2) = _patches(existing)
    with (
        p1,
        p2,
        patch.object(
            kyc_services, "verify_civil", new=AsyncMock(return_value=CIVIL)
        ) as civil,
        patch.object(services, "upsert_admin_profile", new=AsyncMock()),
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    civil.assert_awaited_once()
    assert civil.await_args.args[0] == "0012345678"
    assert existing.civil_data == CIVIL
    assert existing.civil_verified_at is not None


@pytest.mark.asyncio
async def test_admin_kyc_mismatch_is_reported() -> None:
    user, (p1, p2) = _patches(SimpleNamespace(save=AsyncMock()))
    with (
        p1,
        p2,
        patch.object(
            kyc_services,
            "verify_civil",
            new=AsyncMock(side_effect=BadRequestError(error_code="x")),
        ),
        pytest.raises(BadRequestError),
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))


@pytest.mark.asyncio
async def test_admin_kyc_saves_without_registry_when_unavailable() -> None:
    existing = SimpleNamespace(
        civil_data=None, civil_verified_at=None, save=AsyncMock()
    )
    user, (p1, p2) = _patches(existing)
    with (
        p1,
        p2,
        patch.object(
            kyc_services,
            "verify_civil",
            new=AsyncMock(side_effect=ServiceUnavailableError()),
        ),
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    assert existing.civil_data is None
    existing.save.assert_awaited_once()


def test_civil_names_use_persian_letters() -> None:
    """The registry returns Arabic ي/ك; names must be stored with ی/ک."""
    first, last = kyc_services.civil_name_parts({
        "firstName": "محمدمهدي",
        "lastName": "كياني",
    })
    assert (first, last) == ("محمدمهدی", "کیانی")


@pytest.mark.asyncio
async def test_admin_kyc_fills_profile_names_and_empty_user_name() -> None:
    """Civil data is authoritative: names go to the profile; blank user.name fills."""
    existing = SimpleNamespace(
        civil_data=None, civil_verified_at=None, save=AsyncMock()
    )
    user, (p1, p2) = _patches(existing)
    user.name = None
    user.save = AsyncMock()
    civil = {"firstName": "محمدمهدي", "lastName": "كياني"}
    with (
        p1,
        p2,
        patch.object(kyc_services, "verify_civil", new=AsyncMock(return_value=civil)),
        patch.object(services, "upsert_admin_profile", new=AsyncMock()) as profile,
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    profile.assert_awaited_once_with(
        user=user, first_name="محمدمهدی", last_name="کیانی"
    )
    assert user.name == "محمدمهدی کیانی"
    user.save.assert_awaited()


@pytest.mark.asyncio
async def test_admin_kyc_keeps_an_existing_user_name() -> None:
    existing = SimpleNamespace(
        civil_data=None, civil_verified_at=None, save=AsyncMock()
    )
    user, (p1, p2) = _patches(existing)
    user.name = "نام دستی"
    user.save = AsyncMock()
    with (
        p1,
        p2,
        patch.object(kyc_services, "verify_civil", new=AsyncMock(return_value=CIVIL)),
        patch.object(services, "upsert_admin_profile", new=AsyncMock()),
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    assert user.name == "نام دستی"
