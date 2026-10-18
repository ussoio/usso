"""Tests for reactivating incomplete-KYC inactive users."""

from types import SimpleNamespace
from unittest import mock

import pytest

from apps.identity.kyc import reactivate


def _query(items: list) -> mock.MagicMock:
    query = mock.MagicMock()
    query.to_list = mock.AsyncMock(return_value=items)
    return query


def _user(uid: str) -> SimpleNamespace:
    return SimpleNamespace(uid=uid, name=uid, is_active=False, save=mock.AsyncMock())


@pytest.mark.asyncio
async def test_dry_run_reports_only_users_without_approved_kyc() -> None:
    users = [_user("u1"), _user("u2"), _user("u3")]
    with (
        mock.patch.object(
            reactivate.KYC,
            "find",
            return_value=_query([SimpleNamespace(user_id="u2")]),
        ),
        mock.patch.object(reactivate.User, "find", return_value=_query(users)),
    ):
        report = await reactivate.reactivate_incomplete_kyc_users(
            tenant_id="t1",
            exclude={"u3"},
        )
    assert report["matched"] == 1
    assert report["users"] == [{"uid": "u1", "name": "u1"}]
    assert report["applied"] is False
    users[0].save.assert_not_awaited()
    assert users[0].is_active is False


@pytest.mark.asyncio
async def test_apply_reactivates_matched_users() -> None:
    user = _user("u1")
    with (
        mock.patch.object(reactivate.KYC, "find", return_value=_query([])),
        mock.patch.object(reactivate.User, "find", return_value=_query([user])),
    ):
        report = await reactivate.reactivate_incomplete_kyc_users(
            tenant_id="t1",
            apply=True,
        )
    assert report["applied"] is True
    assert user.is_active is True
    user.save.assert_awaited_once()
