"""Focused branch coverage for the Bale Safir channel."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from apps.tenant.messaging.channels.bale import (
    BaleAuthorizError,
    BaleSafirAPI,
    BaleSafirChannel,
    BaleSafirConfig,
)


def _api() -> BaleSafirAPI:
    return BaleSafirAPI(client_id="client", client_secret="secret")


def test_is_expired_for_missing_past_and_future_expiry() -> None:
    api = _api()
    try:
        assert api.is_expired is True
        api._expired_at = datetime.now() - timedelta(seconds=1)
        assert api.is_expired is True
        api._expired_at = datetime.now() + timedelta(seconds=60)
        assert api.is_expired is False
    finally:
        api.close()


def test_authenticate_skips_when_token_is_valid() -> None:
    api = _api()
    api._expired_at = datetime.now() + timedelta(seconds=60)
    with patch.object(api, "post") as post:
        api.authenticate()
    post.assert_not_called()
    api.close()


def test_authenticate_success_sets_header_and_expiry() -> None:
    api = _api()
    response = MagicMock()
    response.json.return_value = {"access_token": "token", "expires_in": 120}
    with patch.object(api, "post", return_value=response) as post:
        api.authenticate()
    post.assert_called_once_with(
        "/auth/token",
        data={
            "grant_type": "client_credentials",
            "scope": "read",
            "client_id": "client",
            "client_secret": "secret",
        },
    )
    assert api.access_token == "token"
    assert api._last_auth is not None
    assert api.is_expired is False
    api.close()


def test_authenticate_raises_without_access_token() -> None:
    api = _api()
    response = MagicMock()
    response.json.return_value = {"expires_in": 120}
    with (
        patch.object(api, "post", return_value=response),
        pytest.raises(BaleAuthorizError, match="login failed"),
    ):
        api.authenticate()
    api.close()


def test_access_token_returns_none_when_expired() -> None:
    api = _api()
    api._access_token = "old"
    api._expired_at = datetime.now() - timedelta(seconds=1)
    assert api.access_token is None
    api.close()


def test_send_otp_posts_expected_json() -> None:
    api = _api()
    response = MagicMock()
    with patch.object(api, "post", return_value=response) as post:
        assert api.send_otp(phone="989121234567", otp=123456) is response
    post.assert_called_once_with(
        "/send_otp", json={"phone": "989121234567", "otp": 123456}
    )
    api.close()


def test_bale_channel_send_authenticates_sends_and_parses_response() -> None:
    channel = object.__new__(BaleSafirChannel)
    channel.config = BaleSafirConfig(client_id="client", client_secret="secret")
    response = MagicMock()
    response.json.return_value = {"success": True}
    bale = MagicMock()
    bale.__enter__.return_value = bale
    bale.__exit__.return_value = None
    bale.send_otp.return_value = response
    with patch(
        "apps.tenant.messaging.channels.bale.BaleSafirAPI", return_value=bale
    ) as api_cls:
        result = channel.send(to="989121234567", otp="123456")
    assert result == {"success": True}
    api_cls.assert_called_once_with(client_id="client", client_secret="secret")
    bale.authenticate.assert_called_once_with()
    bale.send_otp.assert_called_once_with(phone="989121234567", otp=123456)
    response.raise_for_status.assert_called_once_with()
