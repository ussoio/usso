"""test_email module."""

import pytest

from apps.tenant.messaging.channels.email import (
    SMTPConfig,
    send_email,
)
from apps.tenant.messaging.services import send
from apps.tenant.models import Tenant


@pytest.mark.timeout(10)
def test_send_email(rensend_api_key: str, test_email: str) -> None:
    """Test sending an email via SMTP."""
    if not test_email:
        pytest.skip("test_email is not set")

    smtp_config = SMTPConfig(
        host="smtp.resend.com",
        port=465,
        username="resend",
        password=rensend_api_key,
        sender="no-reply@uln.me",
    )

    send_email(
        smtp_config=smtp_config,
        to_email=test_email,
        subject="test",
        text="salam",
    )


@pytest.mark.timeout(10)
def test_tenant_email(test_email: str, messaging_tenant: Tenant) -> None:
    """Test sending a templated email via the tenant messaging service."""
    if not test_email:
        pytest.skip("test_email is not set")

    send(
        tenant=messaging_tenant,
        channel="email",
        to=test_email,
        template_type="verification",
        context={
            "user": {"name": "mahdi"},
            "tenant": messaging_tenant,
            "verification_url": "https://uln.me/verify",
            "expiry_minutes": "30",
        },
    )
