"""Unit tests for magic-link payload helper."""

from unittest.mock import MagicMock, patch

import pytest

from apps.identity.auth.services.magic_link import magic_link_payload
from apps.identity.auth.services.message import (
    _generate_random_otp,
)
from server.exceptions import UnauthorizedError


def test_magic_link_payload_rejects_untrusted_issuer() -> None:
    """Untrusted issuers raise UnauthorizedError before JWT verify."""
    tenant = MagicMock()
    tenant.secrets.trusted_identity_providers = {}
    with (
        patch(
            "apps.identity.auth.services.magic_link.get_tenant_url",
            return_value="https://sso.test",
        ),
        patch("apps.identity.auth.services.magic_link.UnverifiedJWT") as unverified,
    ):
        unverified.return_value.unverified_payload = {"iss": "https://evil.test"}
        with pytest.raises(UnauthorizedError) as exc:
            magic_link_payload("tok", tenant, url="https://app.test")
        assert exc.value.error_code == "invalid_token"


def test_generate_random_otp_length() -> None:
    """OTP generator returns an int within the requested digit width."""
    otp = _generate_random_otp(6)
    assert isinstance(otp, int)
    assert 0 <= otp < 1_000_000
