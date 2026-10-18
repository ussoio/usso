"""Debug configuration must never weaken password or OTP verification."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi_mongo_base.core import config as fmb_config

from apps.identity.auth.services import message
from apps.identity.user import services
from server.config import Settings
from utils.hasher import PasswordHasherService


@pytest.mark.parametrize("debug", ["1", "true", "True", "0"])
@pytest.mark.parametrize("presented", ["111111", "000000", "123456"])
def test_debug_does_not_accept_incorrect_password(
    debug: str, presented: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Known test values must still be verified against the stored hash."""
    monkeypatch.setenv("DEBUG", debug)
    hashed = PasswordHasherService().hash_password("a-different-test-secret")
    assert not services._verify_password_like(
        credential=SimpleNamespace(secret=hashed),
        secret=SimpleNamespace(secret=presented),
    )


@pytest.mark.parametrize("presented", ["valid-test-secret", "123456", "000000"])
def test_debug_preserves_valid_password(
    presented: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real matching password remains usable with debug enabled."""
    monkeypatch.setenv("DEBUG", "1")
    hashed = PasswordHasherService().hash_password(presented)
    assert services._verify_password_like(
        credential=SimpleNamespace(secret=hashed),
        secret=SimpleNamespace(secret=presented),
    )


@pytest.mark.parametrize("debug", [False, True])
def test_otp_uses_csprng_in_every_mode(
    debug: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debug must still call the CSPRNG rather than return a fixed OTP."""
    monkeypatch.setattr(fmb_config.Settings, "debug", debug)
    monkeypatch.setattr(Settings, "debug", debug)
    with patch.object(message.secrets, "randbelow", return_value=42) as random:
        assert message._generate_random_otp(6) == 42
    random.assert_called_once_with(10**6)
