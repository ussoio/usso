"""Unit tests for OAuth device authorization (RFC 8628) helpers."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi_mongo_base.utils import timezone

from apps.tenant.integration import device_code as dc
from apps.tenant.integration.schemas import GrantType, OuathDeviceAuthorizationStatus
from server.exceptions import BadRequestError


def test_grant_type_device_code_is_rfc_8628_urn() -> None:
    """Device grant uses the standard URN value."""
    assert GrantType.DEVICE_CODE == "urn:ietf:params:oauth:grant-type:device_code"


def test_generate_user_code_format() -> None:
    """User codes are XXXX-XXXX with unambiguous alphabet."""
    code = dc.generate_user_code()
    assert len(code) == 9
    assert code[4] == "-"
    body = code.replace("-", "")
    assert body.isupper()
    assert all(ch in dc.USER_CODE_ALPHABET for ch in body)


def test_normalize_user_code_strips_separators() -> None:
    """Lookup ignores dashes/spaces and case."""
    assert dc.normalize_user_code("ab cd-efgh") == "ABCDEFGH"
    assert dc.normalize_user_code("ABCD-EFGH") == "ABCDEFGH"


def test_verification_uri_complete_appends_user_code() -> None:
    """RFC verification_uri_complete includes user_code query param."""
    uri = dc.build_verification_uri_complete(
        "https://sso.example.test/device",
        "ABCD-EFGH",
    )
    assert uri == "https://sso.example.test/device?user_code=ABCD-EFGH"


def test_client_allows_device_code() -> None:
    """Clients must advertise the device_code grant."""
    allowed = SimpleNamespace(grant_types=[GrantType.DEVICE_CODE])
    denied = SimpleNamespace(grant_types=[GrantType.AUTHORIZATION_CODE])
    assert dc.client_allows_device_code(allowed) is True
    assert dc.client_allows_device_code(denied) is False


def test_assert_poll_interval_raises_slow_down() -> None:
    """Polling faster than interval yields slow_down."""
    now = datetime.now(timezone.tz)
    auth = SimpleNamespace(
        interval=5,
        last_polled_at=now - timedelta(seconds=1),
    )
    with pytest.raises(BadRequestError) as exc:
        dc.assert_poll_interval(auth, now=now)
    assert exc.value.error_code == "slow_down"


def test_assert_poll_interval_allows_after_wait() -> None:
    """Polling after interval is allowed."""
    now = datetime.now(timezone.tz)
    auth = SimpleNamespace(
        interval=5,
        last_polled_at=now - timedelta(seconds=6),
    )
    dc.assert_poll_interval(auth, now=now)


def test_poll_status_pending() -> None:
    """Pending authorization maps to authorization_pending."""
    auth = SimpleNamespace(
        status=OuathDeviceAuthorizationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(minutes=5),
        is_consumed=False,
    )
    with pytest.raises(BadRequestError) as exc:
        dc.raise_if_not_ready(auth)
    assert exc.value.error_code == "authorization_pending"


def test_poll_status_denied() -> None:
    """Denied authorization maps to access_denied."""
    auth = SimpleNamespace(
        status=OuathDeviceAuthorizationStatus.DENIED,
        expires_at=datetime.now(timezone.tz) + timedelta(minutes=5),
        is_consumed=False,
    )
    with pytest.raises(BadRequestError) as exc:
        dc.raise_if_not_ready(auth)
    assert exc.value.error_code == "access_denied"


def test_poll_status_expired() -> None:
    """Expired device codes map to expired_token."""
    auth = SimpleNamespace(
        status=OuathDeviceAuthorizationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) - timedelta(seconds=1),
        is_consumed=False,
    )
    with pytest.raises(BadRequestError) as exc:
        dc.raise_if_not_ready(auth)
    assert exc.value.error_code == "expired_token"


def test_resolve_scopes_filters_to_client_allowed() -> None:
    """Requested scopes are intersected with client allowed_scopes."""
    client = SimpleNamespace(
        allowed_scopes=[
            SimpleNamespace(value="openid"),
            SimpleNamespace(value="profile"),
            "email",
        ]
    )
    scopes = dc.resolve_device_scopes(client, "openid admin profile")
    assert scopes == ["openid", "profile"]


@pytest.mark.asyncio
async def test_create_device_authorization_persists_codes() -> None:
    """Creating a device auth stores device_code and user_code."""
    tenant = SimpleNamespace(uid="t1", primary_url="https://sso.example.test")
    tenant.get_frontend_url = mock.MagicMock(
        return_value="https://sso.example.test/api/sso/v1/device"
    )
    client = SimpleNamespace(
        client_id="uc_1",
        user_id="owner-1",
        grant_types=[GrantType.DEVICE_CODE],
        allowed_scopes=["openid", "profile"],
        is_active=True,
    )
    saved = []

    class FakeOuathDeviceAuthorization:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)
            self.uid = "da1"

        async def save(self) -> None:
            saved.append(self)

    with (
        mock.patch(
            "apps.tenant.integration.device_code.models.OuathDeviceAuthorization",
            FakeOuathDeviceAuthorization,
        ),
        mock.patch(
            "apps.tenant.integration.device_code.generate_user_code",
            return_value="ABCD-EFGH",
        ),
        mock.patch(
            "apps.tenant.integration.device_code.generate_device_code",
            return_value="device-secret",
        ),
    ):
        response = await dc.create_device_authorization(
            tenant=tenant,
            client=client,
            scope="openid profile",
        )

    assert response.device_code == "device-secret"
    assert response.user_code == "ABCD-EFGH"
    assert response.interval == dc.DEFAULT_INTERVAL
    assert "user_code=ABCD-EFGH" in response.verification_uri_complete
    assert len(saved) == 1
    assert saved[0].user_code_normalized == "ABCDEFGH"
