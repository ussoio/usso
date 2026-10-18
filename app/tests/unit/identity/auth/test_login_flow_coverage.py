"""Focused unit coverage for login-flow branch behavior."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.identity.auth.enums import (
    AuthIdentifier,
    AuthSecret,
    AuthStep,
    LoginStatus,
    OTPDeliveryStatus,
)
from apps.identity.auth.services import login_flow as flow
from apps.identity.user.models import User
from server.exceptions import BadRequestError, ForbiddenError, UnauthorizedError


def _tenant(
    *,
    registration_allowed: bool = True,
    invite_only: bool = False,
    approval_mode: str = "none",
    login_flow: object | None = None,
) -> SimpleNamespace:
    if login_flow is None:
        login_flow = SimpleNamespace(
            allowed_identifiers=[AuthIdentifier.EMAIL, AuthIdentifier.USERNAME],
            steps=[AuthStep(methods=[AuthSecret.PASSWORD], required_num=1)],
        )
    return SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            auth=SimpleNamespace(login_flow=login_flow),
            registration=SimpleNamespace(
                is_allowed=registration_allowed,
                invite_only=invite_only,
                approval_mode=approval_mode,
            ),
        ),
    )


def _request(**overrides: object) -> SimpleNamespace:
    values = {
        "type": AuthIdentifier.EMAIL,
        "identifier": "alice@example.test",
        "method": AuthSecret.PASSWORD,
        "secret": "secret",
        "referral_code": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _user(**overrides: object) -> MagicMock:
    user = MagicMock(spec=User)
    user.uid = "user-1"
    user.tenant_id = "tenant-1"
    user.is_active = False
    user.mfa_enabled = False
    user.mfa_steps = None
    user.current_identifier = None
    user.save = AsyncMock()
    user.get_credentials = AsyncMock(return_value=[])
    for name, value in overrides.items():
        setattr(user, name, value)
    return user


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"secret": None},
        {"secret": ""},
        {"method": None},
    ],
)
async def test_process_login_flow_requires_explicit_authentication_proof(
    overrides: dict[str, object],
) -> None:
    with (
        patch.object(flow, "find_user", new_callable=AsyncMock) as find_user,
        pytest.raises(UnauthorizedError) as exc,
    ):
        await flow.process_login_flow(
            login_request=_request(**overrides),
            tenant=_tenant(),
        )
    assert exc.value.error_code == "invalid_credentials"
    find_user.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_referral_code_missing_and_not_found() -> None:
    referral, error = await flow.check_referral_code(
        referral_code=None, tenant_id="tenant-1"
    )
    assert referral is None
    assert isinstance(error, ForbiddenError)

    with patch.object(
        flow.ReferralCode, "get_by_code", new_callable=AsyncMock, return_value=None
    ):
        referral, error = await flow.check_referral_code(
            referral_code="INVITE", tenant_id="tenant-1"
        )
    assert referral is None
    assert isinstance(error, ForbiddenError)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "referral",
    [
        SimpleNamespace(
            is_active=False, expires_at=None, max_usage=None, usage_count=0
        ),
        SimpleNamespace(
            is_active=True,
            expires_at=datetime.now(timezone.tz) - timedelta(seconds=1),
            max_usage=None,
            usage_count=0,
        ),
        SimpleNamespace(is_active=True, expires_at=None, max_usage=2, usage_count=2),
    ],
)
async def test_check_referral_code_rejects_unusable_codes(referral: object) -> None:
    with patch.object(
        flow.ReferralCode,
        "get_by_code",
        new_callable=AsyncMock,
        return_value=referral,
    ):
        result, error = await flow.check_referral_code(
            referral_code="INVITE", tenant_id="tenant-1"
        )
    assert result is None
    assert isinstance(error, ForbiddenError)


@pytest.mark.asyncio
async def test_check_referral_code_success() -> None:
    referral = SimpleNamespace(
        is_active=True, expires_at=None, max_usage=3, usage_count=1
    )
    with patch.object(
        flow.ReferralCode,
        "get_by_code",
        new_callable=AsyncMock,
        return_value=referral,
    ):
        result, error = await flow.check_referral_code(
            referral_code="INVITE", tenant_id="tenant-1"
        )
    assert result is referral
    assert error is None


@pytest.mark.asyncio
async def test_register_new_user_registration_disabled() -> None:
    assert (
        await flow.register_new_user(
            login_request=_request(), tenant=_tenant(registration_allowed=False)
        )
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method",
    [
        AuthSecret.EMAIL_OTP,
        AuthSecret.OAUTH,
        AuthSecret.MAGIC_LINK,
        AuthSecret.TELEGRAM_TOKEN,
        AuthSecret.WEBAUTHN,
    ],
)
async def test_register_new_user_rejects_unverified_methods(
    method: AuthSecret,
) -> None:
    with pytest.raises(UnauthorizedError) as exc:
        await flow.register_new_user(
            login_request=_request(method=method),
            tenant=_tenant(),
        )
    assert exc.value.error_code == "unverified_registration_method"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "flag"),
    [
        (AuthSecret.OAUTH, "oauth_verified"),
        (AuthSecret.MAGIC_LINK, "magic_link_verified"),
        (AuthSecret.TELEGRAM_TOKEN, "telegram_verified"),
    ],
)
async def test_register_new_user_accepts_internally_verified_methods(
    method: AuthSecret,
    flag: str,
) -> None:
    user = _user()
    with (
        patch.object(
            flow,
            "check_referral_code",
            new_callable=AsyncMock,
            return_value=(None, None),
        ),
        patch.object(
            flow,
            "create_user",
            new_callable=AsyncMock,
            return_value=user,
        ),
    ):
        result = await flow.register_new_user(
            login_request=_request(method=method),
            tenant=_tenant(),
            **{flag: True},
        )
    assert result is user


@pytest.mark.asyncio
async def test_register_new_user_invite_only_raises_error() -> None:
    error = ForbiddenError(detail="invite required")
    with (
        patch.object(
            flow,
            "check_referral_code",
            new_callable=AsyncMock,
            return_value=(None, error),
        ),
        pytest.raises(ForbiddenError),
    ):
        await flow.register_new_user(
            login_request=_request(), tenant=_tenant(invite_only=True)
        )


@pytest.mark.asyncio
async def test_register_new_user_rejects_reserved_username() -> None:
    with (
        patch.object(
            flow,
            "check_referral_code",
            new_callable=AsyncMock,
            return_value=(None, None),
        ),
        patch.object(flow.validators, "reserved", {"reserved"}),
        pytest.raises(BadRequestError) as exc,
    ):
        await flow.register_new_user(
            login_request=_request(type=AuthIdentifier.USERNAME, identifier="Reserved"),
            tenant=_tenant(),
        )
    assert exc.value.error_code == "invalid_username"


@pytest.mark.asyncio
async def test_register_new_user_success_consumes_referral() -> None:
    referral = SimpleNamespace(usage_count=1)
    user = _user()
    with (
        patch.object(
            flow,
            "check_referral_code",
            new_callable=AsyncMock,
            return_value=(referral, None),
        ),
        patch.object(
            flow, "create_user", new_callable=AsyncMock, return_value=user
        ) as create,
        patch(
            "apps.identity.referral.services.consume_referral_code",
            new=AsyncMock(return_value=True),
        ) as consume,
        patch("apps.identity.referral.services.on_referral_registration") as notify,
    ):
        result = await flow.register_new_user(
            login_request=_request(),
            tenant=_tenant(),
            name="Alice",
            telegram_verified=True,
        )
    assert result is user
    assert create.await_args.kwargs["name"] == "Alice"
    assert "telegram_verified" not in create.await_args.kwargs
    consume.assert_awaited_once_with(referral)
    notify.assert_called_once()


@pytest.mark.asyncio
async def test_register_new_user_releases_reserved_referral_on_failure() -> None:
    referral = SimpleNamespace(usage_count=1)
    with (
        patch.object(
            flow,
            "check_referral_code",
            new=AsyncMock(return_value=(referral, None)),
        ),
        patch(
            "apps.identity.referral.services.consume_referral_code",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            flow,
            "create_user",
            new=AsyncMock(side_effect=RuntimeError("database failure")),
        ),
        patch(
            "apps.identity.referral.services.release_referral_code",
            new=AsyncMock(),
        ) as release,
        pytest.raises(RuntimeError),
    ):
        await flow.register_new_user(
            login_request=_request(),
            tenant=_tenant(invite_only=True),
        )
    release.assert_awaited_once_with(referral)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier", "method", "expected"),
    [
        (None, AuthSecret.EMAIL_OTP, False),
        (SimpleNamespace(verified_at=object()), AuthSecret.EMAIL_OTP, True),
        (SimpleNamespace(verified_at=None), None, False),
        (
            SimpleNamespace(verified_at=None, type=AuthIdentifier.PHONE),
            AuthSecret.PASSWORD,
            False,
        ),
        (
            SimpleNamespace(verified_at=None, type=AuthIdentifier.PHONE),
            AuthSecret.EMAIL_OTP,
            False,
        ),
    ],
)
async def test_verify_identifier_early_returns(
    identifier: object, method: AuthSecret | None, expected: bool
) -> None:
    assert (
        await flow.verify_identifier(
            user=SimpleNamespace(current_identifier=identifier),
            login_request=_request(method=method),
        )
        is expected
    )


@pytest.mark.asyncio
async def test_verify_identifier_marks_matching_identifier_verified() -> None:
    identifier = SimpleNamespace(
        verified_at=None, type=AuthIdentifier.EMAIL, save=AsyncMock()
    )
    result = await flow.verify_identifier(
        user=SimpleNamespace(current_identifier=identifier),
        login_request=_request(method=AuthSecret.EMAIL_OTP),
    )
    assert result is True
    assert identifier.verified_at is not None
    identifier.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_activate_user_if_eligible_already_active() -> None:
    user = _user(is_active=True)
    with patch.object(
        flow, "verify_identifier", new_callable=AsyncMock, return_value=False
    ):
        assert await flow.activate_user_if_eligible(
            user=user, tenant=_tenant(), login_request=_request()
        )
    user.save.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "verified", "expected", "saved"),
    [
        ("none", False, True, True),
        ("identifier", False, False, False),
        ("identifier", True, True, True),
        ("manual_review", True, False, False),
        ("unknown", True, False, False),
    ],
)
async def test_activate_user_if_eligible_modes(
    mode: str, verified: bool, expected: bool, saved: bool
) -> None:
    user = _user()
    with patch.object(
        flow, "verify_identifier", new_callable=AsyncMock, return_value=verified
    ):
        result = await flow.activate_user_if_eligible(
            user=user,
            tenant=_tenant(approval_mode=mode),
            login_request=_request(),
        )
    assert result is expected
    assert bool(user.save.await_count) is saved


@pytest.mark.asyncio
@pytest.mark.parametrize(("kyc", "expected"), [(None, False), (object(), True)])
async def test_activate_user_if_eligible_additional_uses_kyc(
    kyc: object | None, expected: bool
) -> None:
    user = _user()
    with (
        patch.object(
            flow, "verify_identifier", new_callable=AsyncMock, return_value=True
        ),
        patch(
            "apps.identity.kyc.models.KYC.get_by_user_id",
            new_callable=AsyncMock,
            return_value=kyc,
        ),
    ):
        result = await flow.activate_user_if_eligible(
            user=user,
            tenant=_tenant(approval_mode="additional"),
            login_request=_request(),
        )
    assert result is expected


def test_validate_flow_completion_incomplete_and_complete() -> None:
    first = SimpleNamespace(
        methods=[AuthSecret.PASSWORD, AuthSecret.EMAIL_OTP], required_num=1
    )
    second = SimpleNamespace(methods=[AuthSecret.TOTP], required_num=1)
    login_flow = SimpleNamespace(steps=[first, second])
    assert flow.validate_flow_completion(login_flow=login_flow, amr=[]) is first
    assert (
        flow.validate_flow_completion(
            login_flow=login_flow, amr=[AuthSecret.PASSWORD, AuthSecret.TOTP]
        )
        is None
    )


def test_determine_otp_delivery_requestable_and_sent() -> None:
    mixed = SimpleNamespace(methods=[AuthSecret.PASSWORD, AuthSecret.EMAIL_OTP])
    otp_only = SimpleNamespace(methods=[AuthSecret.PHONE_OTP])
    assert flow._determine_otp_delivery(mixed) == {
        AuthSecret.EMAIL_OTP: OTPDeliveryStatus.REQUESTABLE
    }
    assert flow._determine_otp_delivery(otp_only) == {
        AuthSecret.PHONE_OTP: OTPDeliveryStatus.SENT
    }


@pytest.mark.parametrize(
    ("code", "exception"),
    [("registration_failed", BadRequestError), ("unknown_failure", UnauthorizedError)],
)
def test_raise_login_flow_failed_known_and_unknown(
    code: str, exception: type[Exception]
) -> None:
    with pytest.raises(exception) as exc:
        flow._raise_login_flow_failed(error_code=code, detail="failed")
    assert exc.value.error_code == code


@pytest.mark.asyncio
async def test_resolve_login_attempt_error_branches() -> None:
    identifier = SimpleNamespace(type=AuthIdentifier.PHONE, identifier="+989121234567")
    with pytest.raises(BadRequestError) as not_allowed:
        await flow.resolve_login_attempt(identifier=identifier, tenant=_tenant())
    assert not_allowed.value.error_code == "identifier_not_allowed"

    with patch.object(flow, "find_user", new_callable=AsyncMock, return_value=None):
        result = await flow.resolve_login_attempt(
            identifier=SimpleNamespace(
                type=AuthIdentifier.EMAIL, identifier="a@example.test"
            ),
            tenant=_tenant(registration_allowed=False),
        )
    assert result.user is None

    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=None),
        patch.object(flow, "validate_flow_completion", return_value=None),
        pytest.raises(BadRequestError) as invalid_flow,
    ):
        await flow.resolve_login_attempt(
            identifier=SimpleNamespace(
                type=AuthIdentifier.EMAIL, identifier="a@example.test"
            ),
            tenant=_tenant(),
        )
    assert invalid_flow.value.error_code == "invalid_flow"


@pytest.mark.asyncio
async def test_resolve_login_attempt_success_includes_otp_delivery() -> None:
    step = AuthStep(methods=[AuthSecret.PASSWORD, AuthSecret.EMAIL_OTP], required_num=1)
    user = _user()
    user.get_credentials.return_value = [object()]
    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=user),
        patch.object(flow, "validate_flow_completion", return_value=step),
    ):
        result = await flow.resolve_login_attempt(
            identifier=SimpleNamespace(
                type=AuthIdentifier.EMAIL, identifier="a@example.test"
            ),
            tenant=_tenant(),
        )
    assert result.status == LoginStatus.CHALLENGE_REQUIRED
    assert result.otp_delivery[AuthSecret.EMAIL_OTP] == OTPDeliveryStatus.REQUESTABLE


@pytest.mark.asyncio
async def test_process_login_flow_client_and_registration_failures() -> None:
    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=None),
        pytest.raises(UnauthorizedError) as client_error,
    ):
        await flow.process_login_flow(
            login_request=_request(type=AuthIdentifier.CLIENT_ID), tenant=_tenant()
        )
    assert client_error.value.error_code == "client_not_found"

    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=None),
        patch.object(
            flow, "register_new_user", new_callable=AsyncMock, return_value=None
        ),
        pytest.raises(UnauthorizedError) as registration_error,
    ):
        await flow.process_login_flow(login_request=_request(), tenant=_tenant())
    assert registration_error.value.error_code == "invalid_credentials"


@pytest.mark.asyncio
async def test_process_login_flow_invalid_credentials() -> None:
    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=_user()),
        patch.object(
            flow, "authenticate_user", new_callable=AsyncMock, return_value=False
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await flow.process_login_flow(login_request=_request(), tenant=_tenant())
    assert exc.value.error_code == "invalid_credentials"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("next_step", "active", "expected"),
    [
        (
            AuthStep(methods=[AuthSecret.TOTP], required_num=1),
            True,
            LoginStatus.MFA_REQUIRED,
        ),
        (None, False, LoginStatus.VERIFICATION_REQUIRED),
        (None, True, LoginStatus.COMPLETED),
    ],
)
async def test_process_login_flow_result_statuses(
    next_step: object | None, active: bool, expected: LoginStatus
) -> None:
    user = _user()
    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=user),
        patch.object(
            flow, "authenticate_user", new_callable=AsyncMock, return_value=True
        ),
        patch.object(flow, "validate_flow_completion", return_value=next_step),
        patch.object(
            flow,
            "activate_user_if_eligible",
            new_callable=AsyncMock,
            return_value=active,
        ),
    ):
        result = await flow.process_login_flow(
            login_request=_request(), tenant=_tenant()
        )
    assert result.status == expected


@pytest.mark.asyncio
async def test_process_login_flow_requires_user_mfa_after_main_flow() -> None:
    mfa_step = AuthStep(methods=[AuthSecret.TOTP], required_num=1)
    user = _user(
        mfa_enabled=True,
        mfa_steps=SimpleNamespace(steps=[mfa_step]),
    )
    with (
        patch.object(flow, "find_user", new_callable=AsyncMock, return_value=user),
        patch.object(
            flow, "authenticate_user", new_callable=AsyncMock, return_value=True
        ),
    ):
        result = await flow.process_login_flow(
            login_request=_request(), tenant=_tenant()
        )

    assert result.status == LoginStatus.MFA_REQUIRED
    assert result.next_step == mfa_step


@pytest.mark.asyncio
async def test_activation_dispatches_user_activated_webhook_once() -> None:
    user = _user()
    tenant = _tenant(approval_mode="identifier")
    with (
        patch.object(
            flow, "verify_identifier", new_callable=AsyncMock, return_value=True
        ),
        patch.object(flow, "dispatch_tenant_webhooks") as dispatch,
    ):
        assert await flow.activate_user_if_eligible(
            user=user, tenant=tenant, login_request=_request()
        )
        # A second login finds the user active and must not fire the event again.
        assert await flow.activate_user_if_eligible(
            user=user, tenant=tenant, login_request=_request()
        )

    dispatch.assert_called_once()
    kwargs = dispatch.call_args.kwargs
    assert kwargs["event"] == "user.activated"
    assert kwargs["payload"]["user_id"] == user.uid
    assert kwargs["payload"]["tenant_id"] == tenant.uid


@pytest.mark.asyncio
async def test_failed_activation_does_not_dispatch_webhook() -> None:
    with (
        patch.object(
            flow, "verify_identifier", new_callable=AsyncMock, return_value=False
        ),
        patch.object(flow, "dispatch_tenant_webhooks") as dispatch,
    ):
        assert not await flow.activate_user_if_eligible(
            user=_user(),
            tenant=_tenant(approval_mode="identifier"),
            login_request=_request(),
        )
    dispatch.assert_not_called()
