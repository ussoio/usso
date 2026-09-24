"""Tests for messaging queue adapter."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.tenant.messaging.services import (
    QUEUE_KEY,
    _make_serializable,
    enqueue_message,
)


@pytest.mark.asyncio
async def test_enqueue_message_pushes_to_redis() -> None:
    """enqueue_message should RPUSH a JSON payload to the outbox key."""
    mock_redis = AsyncMock()

    with patch("server.db.redis", mock_redis):
        await enqueue_message(
            tenant_id="t1",
            channel="sms",
            to="+989123456789",
            template_type="sms_otp",
            context={"otp_code": "123456"},
        )

    mock_redis.rpush.assert_called_once()
    call_args = mock_redis.rpush.call_args
    assert call_args[0][0] == QUEUE_KEY

    payload = json.loads(call_args[0][1])
    assert payload["tenant_id"] == "t1"
    assert payload["channel"] == "sms"
    assert payload["to"] == "+989123456789"
    assert payload["template_type"] == "sms_otp"
    assert payload["context"]["otp_code"] == "123456"


@pytest.mark.asyncio
async def test_asend_uses_queue_when_enabled() -> None:
    """Enqueue instead of sending inline when MESSAGING_QUEUE_ENABLED=true."""
    from apps.tenant.messaging.services import asend

    mock_tenant = MagicMock()
    mock_tenant.uid = "t1"
    mock_enqueue = AsyncMock()

    with (
        patch("apps.tenant.messaging.services._is_queue_enabled", return_value=True),
        patch("apps.tenant.messaging.services.enqueue_message", mock_enqueue),
    ):
        await asend(
            tenant=mock_tenant,
            channel="sms",
            to="+989123456789",
            template_type="sms_otp",
            context={"otp_code": "123456"},
        )

    mock_enqueue.assert_called_once()
    assert mock_enqueue.call_args.kwargs["tenant_id"] == "t1"


@pytest.mark.asyncio
async def test_asend_sends_inline_when_queue_disabled() -> None:
    """Asend should send inline when MESSAGING_QUEUE_ENABLED is not set."""
    from apps.tenant.messaging.services import asend

    mock_tenant = MagicMock()
    mock_channel = AsyncMock()
    mock_channel.channel_type = "sms"

    with (
        patch("apps.tenant.messaging.services._is_queue_enabled", return_value=False),
        patch(
            "apps.tenant.messaging.services.AbstractChannel.create_channel",
            return_value=mock_channel,
        ),
        patch(
            "apps.tenant.messaging.services.arender_template",
            return_value="Your OTP is 123456",
        ),
    ):
        mock_tenant.config.templates.get.return_value = MagicMock(subject="OTP")
        await asend(
            tenant=mock_tenant,
            channel="sms",
            to="+989123456789",
            template_type="sms_otp",
            context={"otp_code": "123456"},
        )

    mock_channel.asend.assert_called_once()


def test_make_serializable_handles_pydantic() -> None:
    """_make_serializable should convert pydantic models to dicts."""
    mock_model = MagicMock()
    mock_model.model_dump.return_value = {"name": "test"}

    result = _make_serializable({"tenant": mock_model, "code": "123"})
    assert result["tenant"] == {"name": "test"}
    assert result["code"] == "123"
