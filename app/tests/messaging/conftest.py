"""conftest module."""

import os

import dotenv
import pytest

from apps.tenant.messaging.schemas import TenantChannelConfig
from apps.tenant.models import Tenant
from apps.tenant.secrets import TenantSecrets

dotenv.load_dotenv()


@pytest.fixture
def rensend_api_key() -> str:
    """Return the Resend API key from environment."""
    return os.getenv("RESEND_API_KEY")


@pytest.fixture
def test_email() -> str:
    """Return the test email from environment."""
    return os.getenv("TEST_EMAIL")


@pytest.fixture
def kavenegar_api_key() -> str:
    """Return the Kavenegar API key from environment."""
    return os.getenv("KAVENEGAR_API_KEY")


@pytest.fixture
def test_phone() -> str:
    """Return the test phone number from environment."""
    return os.getenv("TEST_PHONE")


@pytest.fixture
def bale_client_config() -> dict[str, str]:
    """Return the Bale client config from environment."""
    return {
        "client_id": os.getenv("USSO_BALE_CLIENT_ID"),
        "client_secret": os.getenv("USSO_BALE_CLIENT_SECRET"),
    }


@pytest.fixture
def messaging_tenant(
    rensend_api_key: str, kavenegar_api_key: str, bale_client_config: dict[str, str]
) -> Tenant:
    """Create a mock messaging tenant with SMS, email, and Bale configs."""
    sms_config = TenantChannelConfig(
        tenant_id="test",
        channel_type="sms",
        provider_name="kavenegar",
        provider_config={"api_key": kavenegar_api_key},
        is_active=True,
    )
    email_config = TenantChannelConfig(
        tenant_id="test",
        channel_type="email",
        provider_name="resend",
        provider_config={
            "host": "smtp.resend.com",
            "port": 465,
            "username": "resend",
            "password": rensend_api_key,
            "sender": "no-reply@uln.me",
        },
        is_active=True,
    )
    bale_config = TenantChannelConfig(
        tenant_id="test",
        channel_type="bale",
        provider_name="bale",
        provider_config=bale_client_config,
        is_active=True,
    )
    return Tenant(
        name="test",
        user_id="test",
        domains=["test.com"],
        secrets=TenantSecrets(
            channel_configs={
                "sms": sms_config,
                "email": email_config,
                "bale": bale_config,
            }
        ),
    )
