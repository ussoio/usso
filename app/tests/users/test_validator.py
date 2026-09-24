"""test_validator module."""

import os

import pytest

from apps.identity.user.validator import JibitClient


@pytest.fixture
def jibit_client() -> JibitClient:
    return JibitClient(
        api_key=os.getenv("JIBIT_API_KEY"),
        secret_key=os.getenv("JIBIT_SECRET_KEY"),
    )


def test_match(jibit_client: JibitClient) -> None:
    phone_number = os.getenv("TEST_PHONE")
    national_code = os.getenv("TEST_NATIONAL_ID")

    if not all([
        phone_number,
        national_code,
        os.getenv("JIBIT_API_KEY"),
        os.getenv("JIBIT_SECRET_KEY"),
        os.getenv("JWT_CONFIG"),
    ]):
        pytest.skip("Jibit integration credentials are not fully configured")

    jibit_client.authenticate()
    assert jibit_client.match(
        phone_number=phone_number,
        national_code=national_code,
    )
    assert not jibit_client.match(
        phone_number=phone_number[:-1] + str((int(phone_number[-1]) + 1) % 10),
        national_code=national_code,
    )
