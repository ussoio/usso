"""Unit tests for OTP create/send helpers in message services."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.identity.auth.enums import AuthIdentifier, AuthSecret, AuthStep
from apps.identity.auth.schemas import OTPRequest
from apps.identity.auth.services import message as message_services
from apps.tenant.messaging.enums import MessageChannelType
from server.exceptions import TooManyRequestsError


def _tenant() -> MagicMock:
    tenant = MagicMock()
    tenant.uid = "t1"
    tenant.primary_domain = "sso.example.test"
    tenant.config.auth.otp_length = 6
    tenant.config.auth.otp_timeout = 300
    tenant.secrets.channel_configs = {
        "sms": object(),
        "bale": object(),
        "email": object(),
    }
    return tenant


def _close_scheduled(coro: object) -> None:
    """Avoid 'coroutine never awaited' when background scheduling is mocked."""
    close = getattr(coro, "close", None)
    if callable(close):
        close()


@pytest.mark.asyncio
async def test_create_otp_sends_and_stores_credential() -> None:
    """create_otp stores a credential and schedules messaging."""
    tenant = _tenant()
    otp_request = OTPRequest(
        type=AuthIdentifier.PHONE,
        identifier="09120000000",
        channel_type=MessageChannelType.SMS,
    )
    user = MagicMock()
    user.uid = "u1"
    channel = MagicMock()
    channel.channel_type = MessageChannelType.SMS

    query = MagicMock()
    query.count = AsyncMock(return_value=0)
    query.sort.return_value.first_or_none = AsyncMock(return_value=None)
    query.find.return_value.update_many = AsyncMock()

    credential = MagicMock()
    credential.save = AsyncMock()
    cred_cls = MagicMock(return_value=credential)
    cred_cls.get_query = MagicMock(return_value=query)

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=MessageChannelType.SMS,
        ),
        patch.object(OTPRequest, "get_channel", return_value=channel),
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, True)),
        ),
        patch.object(message_services, "_generate_random_otp", return_value=123456),
        patch.object(message_services, "Credential", cred_cls),
        patch.object(
            message_services,
            "_schedule_background_task",
            side_effect=_close_scheduled,
        ) as schedule,
    ):
        otp = await message_services.create_otp(
            otp_request=otp_request, tenant=tenant, origin="app.example.test"
        )

    assert otp == 123456
    credential.save.assert_awaited_once()
    schedule.assert_called_once()


@pytest.mark.asyncio
async def test_create_otp_raises_when_too_many_active() -> None:
    """More than three active OTPs raise TooManyRequestsError."""
    tenant = _tenant()
    otp_request = OTPRequest(
        type=AuthIdentifier.EMAIL,
        identifier="user@example.com",
        channel_type=MessageChannelType.EMAIL,
    )
    user = MagicMock()
    user.uid = "u1"
    user.get_identifiers = AsyncMock(
        return_value=[
            SimpleNamespace(type=AuthIdentifier.EMAIL, identifier="user@example.com")
        ]
    )
    channel = MagicMock()
    channel.channel_type = MessageChannelType.EMAIL

    query = SimpleNamespace(count=AsyncMock(return_value=4))
    cred_cls = MagicMock()
    cred_cls.get_query = MagicMock(return_value=query)

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=MessageChannelType.EMAIL,
        ),
        patch.object(OTPRequest, "get_channel", return_value=channel),
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, False)),
        ),
        patch.object(message_services, "Credential", cred_cls),
        pytest.raises(TooManyRequestsError),
    ):
        await message_services.create_otp(otp_request=otp_request, tenant=tenant)


@pytest.mark.asyncio
async def test_check_otp_needed_and_send_phone_branch() -> None:
    """Phone OTP step triggers create_otp for each phone identifier."""
    tenant = _tenant()
    user = MagicMock()
    phone = SimpleNamespace(type=AuthIdentifier.PHONE, identifier="09121111111")
    user.get_identifiers = AsyncMock(return_value=[phone])
    user.get_credentials = AsyncMock(return_value=[])

    next_step = MagicMock(spec=AuthStep)
    next_step.methods = [AuthSecret.PHONE_OTP]

    with (
        patch.object(message_services, "sanitize_origin", return_value="app.test"),
        patch.object(
            message_services, "create_otp", new=AsyncMock(return_value=111111)
        ) as create_otp,
    ):
        await message_services.check_otp_needed_and_send(
            next_step=next_step,
            user=user,
            tenant=tenant,
            origin="app.test",
            amr=[],
        )

    create_otp.assert_awaited_once()
    assert create_otp.await_args.kwargs["otp_request"].type == AuthIdentifier.PHONE


@pytest.mark.asyncio
async def test_check_otp_needed_and_send_email_branch() -> None:
    """Email OTP step triggers create_otp for each email identifier."""
    tenant = _tenant()
    user = MagicMock()
    email = SimpleNamespace(type=AuthIdentifier.EMAIL, identifier="user@example.com")
    user.get_identifiers = AsyncMock(return_value=[email])
    user.get_credentials = AsyncMock(return_value=[])

    next_step = MagicMock(spec=AuthStep)
    next_step.methods = [AuthSecret.EMAIL_OTP]

    with (
        patch.object(message_services, "sanitize_origin", return_value=None),
        patch.object(
            message_services, "create_otp", new=AsyncMock(return_value=222222)
        ) as create_otp,
    ):
        await message_services.check_otp_needed_and_send(
            next_step=next_step,
            user=user,
            tenant=tenant,
            amr=[],
        )

    create_otp.assert_awaited_once()
    assert create_otp.await_args.kwargs["otp_request"].type == AuthIdentifier.EMAIL


@pytest.mark.asyncio
async def test_check_otp_needed_skips_when_already_in_amr() -> None:
    """OTP is not resent when the AMR already includes that method."""
    tenant = _tenant()
    user = MagicMock()
    user.get_identifiers = AsyncMock(return_value=[])
    user.get_credentials = AsyncMock(return_value=[])
    next_step = MagicMock(spec=AuthStep)
    next_step.methods = [AuthSecret.PHONE_OTP]

    with (
        patch.object(message_services, "sanitize_origin", return_value=None),
        patch.object(message_services, "create_otp", new=AsyncMock()) as create_otp,
    ):
        await message_services.check_otp_needed_and_send(
            next_step=next_step,
            user=user,
            tenant=tenant,
            amr=[AuthSecret.PHONE_OTP],
        )
    create_otp.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_otp_uses_existing_identifier_when_user_exists() -> None:
    """Existing users pick matching identifier type when available."""
    tenant = _tenant()
    otp_request = OTPRequest(
        type=AuthIdentifier.PHONE,
        identifier="09129999999",
        channel_type=MessageChannelType.SMS,
    )
    user = MagicMock()
    user.uid = "u1"
    user.get_identifiers = AsyncMock(
        return_value=[
            SimpleNamespace(type=AuthIdentifier.PHONE, identifier="09120000000")
        ]
    )
    channel = MagicMock()
    channel.channel_type = MessageChannelType.SMS

    query = MagicMock()
    query.count = AsyncMock(return_value=1)
    latest = SimpleNamespace(created_at=datetime.now(timezone.tz))
    query.sort.return_value.first_or_none = AsyncMock(return_value=latest)
    query.find.return_value.update_many = AsyncMock()

    credential = MagicMock()
    credential.save = AsyncMock()
    cred_cls = MagicMock(return_value=credential)
    cred_cls.get_query = MagicMock(return_value=query)

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=MessageChannelType.SMS,
        ),
        patch.object(OTPRequest, "get_channel", return_value=channel),
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, False)),
        ),
        patch.object(message_services, "_generate_random_otp", return_value=42),
        patch.object(message_services, "Credential", cred_cls),
        patch.object(
            message_services,
            "_schedule_background_task",
            side_effect=_close_scheduled,
        ) as schedule,
    ):
        otp = await message_services.create_otp(otp_request=otp_request, tenant=tenant)

    assert otp == 42
    schedule.assert_called_once()
    credential.save.assert_awaited_once()
