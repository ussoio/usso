"""Unit tests for Bale messaging channel (mocked network)."""

from unittest.mock import MagicMock, patch

from apps.tenant.messaging.channels.bale import BaleSafirChannel


def test_bale_channel_send_calls_send_otp() -> None:
    """BaleSafirChannel.send authenticates and sends OTP via Safir API."""
    channel = BaleSafirChannel.__new__(BaleSafirChannel)
    channel.config = MagicMock()
    channel.config.model_dump.return_value = {
        "client_id": "cid",
        "client_secret": "csec",
    }

    mock_api = MagicMock()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"ok": True}
    mock_api.send_otp.return_value = mock_resp
    mock_api.__enter__ = MagicMock(return_value=mock_api)
    mock_api.__exit__ = MagicMock(return_value=False)

    with patch(
        "apps.tenant.messaging.channels.bale.BaleSafirAPI",
        return_value=mock_api,
    ):
        result = channel.send(to="09120000000", otp=1234)

    mock_api.authenticate.assert_called_once()
    mock_api.send_otp.assert_called_once_with(phone="09120000000", otp=1234)
    mock_resp.raise_for_status.assert_called_once()
    assert result == {"ok": True}
