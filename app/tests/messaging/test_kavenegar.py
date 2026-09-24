"""test_kavenegar module."""

import pytest

from apps.tenant.messaging.channels.sms import KavenegarSMSChannel
from apps.tenant.models import Tenant


def test_sms_channel(test_phone: str, messaging_tenant: Tenant) -> None:
    """Test sending an SMS via Kavenegar channel."""
    if not test_phone:
        pytest.skip("test_phone is not set")

    channel = KavenegarSMSChannel(tenant=messaging_tenant)
    channel.send(
        to=test_phone,
        message="سلام دوست من",
    )
