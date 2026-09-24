"""Additional unit tests for secure session token helpers."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from usso.user import TokenType

from apps.identity.auth.enums import AuthSecret, LoginStatus
from apps.identity.auth.services.secure_token import (
    extract_secure_token,
    maybe_attach_secure_token,
    require_secure_token,
)
from server.exceptions import ForbiddenError, UnauthorizedError


def _request(**kwargs: object) -> MagicMock:
    request = MagicMock()
    request.cookies = kwargs.get("cookies", {})
    request.headers = kwargs.get("headers", {})
    return request


def test_extract_secure_token_sources() -> None:
    """Cookie, header, and Secure authorization are accepted in order."""
    cookie_name = f"usso-{TokenType.SECURE_TOKEN.value}-token"
    assert (
        extract_secure_token(_request(cookies={cookie_name: "from-cookie"}))
        == "from-cookie"
    )
    assert (
        extract_secure_token(_request(headers={"x-usso-secure-token": "from-header"}))
        == "from-header"
    )
    assert (
        extract_secure_token(_request(headers={"authorization": "Secure tok"})) == "tok"
    )
    assert extract_secure_token(_request()) is None


def test_require_secure_token_missing_and_invalid() -> None:
    """Missing/invalid tokens raise UnauthorizedError."""
    tenant = MagicMock()
    with pytest.raises(UnauthorizedError) as missing:
        require_secure_token(request=_request(), tenant=tenant)
    assert missing.value.error_code == "secure_token_required"

    tenant.secure_auth.user_data_from_token.side_effect = ValueError("bad")
    with pytest.raises(UnauthorizedError) as invalid:
        require_secure_token(
            request=_request(headers={"x-usso-secure-token": "x"}),
            tenant=tenant,
        )
    assert invalid.value.error_code == "secure_token_invalid"

    tenant.secure_auth.user_data_from_token.side_effect = None
    tenant.secure_auth.user_data_from_token.return_value = None
    with pytest.raises(UnauthorizedError) as none_payload:
        require_secure_token(
            request=_request(headers={"x-usso-secure-token": "x"}),
            tenant=tenant,
        )
    assert none_payload.value.error_code == "secure_token_invalid"


def test_require_secure_token_user_mismatch_and_normalize() -> None:
    """Wrong subject is forbidden; UserData-like payloads are normalized."""
    tenant = MagicMock()
    tenant.secure_auth.user_data_from_token.return_value = SimpleNamespace(
        sub="other-user",
        jti="j1",
        iss="https://sso.test",
        aud="https://sso.test",
        iat=1,
        exp=2,
        tenant_id="t1",
        amr=[AuthSecret.PHONE_OTP.value],
        claims=None,
    )
    with pytest.raises(ForbiddenError) as mismatch:
        require_secure_token(
            request=_request(headers={"x-usso-secure-token": "x"}),
            tenant=tenant,
            user_id="user-1",
        )
    assert mismatch.value.error_code == "secure_token_user_mismatch"

    payload = require_secure_token(
        request=_request(headers={"x-usso-secure-token": "x"}),
        tenant=tenant,
        user_id="other-user",
    )
    assert payload.sub == "other-user"
    assert payload.token_type == TokenType.SECURE_TOKEN


def test_maybe_attach_secure_token_only_for_secure_completed_login() -> None:
    """Secure token attaches only for completed secure AMR logins."""
    user = MagicMock(uid="u1", tenant_id="t1")
    tenant = MagicMock()
    tenant.primary_url = "https://sso.test"
    tenant.config.token.get_timeout.return_value = 300
    tenant.sign_jwt.side_effect = lambda payload, **_: "signed"

    payloads: dict = {}
    maybe_attach_secure_token(
        payloads=payloads,
        user=user,
        tenant=tenant,
        status=LoginStatus.COMPLETED,
        amr=["password"],
    )
    assert TokenType.SECURE_TOKEN not in payloads

    maybe_attach_secure_token(
        payloads=payloads,
        user=user,
        tenant=tenant,
        status=LoginStatus.COMPLETED,
        amr=[AuthSecret.PHONE_OTP.value],
    )
    assert TokenType.SECURE_TOKEN in payloads
