"""Tests for authentication flow validation."""

import pytest

from apps.identity.auth.enums import (
    EXCHANGE_TRANSACTION_FLOW,
    GOOGLE_FLOW,
    PASSWORD_WITH_TOTP,
    SIMPLE_PASSWORD,
    AuthFlow,
    AuthIdentifier,
    AuthSecret,
    AuthStep,
)
from apps.identity.auth.services import validate_flow_completion

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def simple_password_flow() -> AuthFlow:
    """Create a simple password flow fixture."""
    return SIMPLE_PASSWORD


@pytest.fixture
def password_with_totp_flow() -> AuthFlow:
    """Password with TOTP flow fixture."""
    return PASSWORD_WITH_TOTP


@pytest.fixture
def exchange_flow() -> AuthFlow:
    """Exchange transaction flow fixture (requires all methods)."""
    return EXCHANGE_TRANSACTION_FLOW


@pytest.fixture
def repetition_flow() -> AuthFlow:
    """Flow with method repetition across steps fixture."""
    return AuthFlow(
        allowed_identifiers=[AuthIdentifier.EMAIL],
        steps=[
            AuthStep(
                methods=[AuthSecret.PASSWORD, AuthSecret.PHONE_OTP],
                required_num=1,
            ),
            AuthStep(methods=[AuthSecret.TOTP, AuthSecret.PHONE_OTP], required_num=1),
        ],
    )


def test_simple_password_flow_completed(
    simple_password_flow: AuthFlow,
) -> None:
    """Test simple password flow when completed."""
    amr = ["password"]
    next_step = validate_flow_completion(login_flow=simple_password_flow, amr=amr)
    assert next_step is None  # All steps completed


def test_simple_password_flow_not_completed(
    simple_password_flow: AuthFlow,
) -> None:
    """Test simple password flow when not completed."""
    amr: list[str] = []  # No methods used
    next_step = validate_flow_completion(login_flow=simple_password_flow, amr=amr)
    assert next_step == simple_password_flow.steps[0]  # First step needs completion


@pytest.mark.parametrize(
    "amr,expected_step",
    [
        (["password"], 1),  # Step 1 completed, need step 2
        (["password", "totp"], None),  # Both steps completed
        (
            ["password", "email/otp"],
            None,
        ),  # Both steps completed with EMAIL_OTP
        ([], 0),  # No steps completed
        (["totp"], 0),  # Wrong method in step 1
    ],
)
def test_password_with_totp_flow_various_scenarios(
    password_with_totp_flow: AuthFlow,
    amr: list[str],
    expected_step: int | None,
) -> None:
    """Test password with TOTP flow with various scenarios."""
    next_step = validate_flow_completion(login_flow=password_with_totp_flow, amr=amr)

    if expected_step is None:
        assert next_step is None
    else:
        assert next_step == password_with_totp_flow.steps[expected_step]


@pytest.mark.parametrize(
    "amr,expected_completed",
    [
        (["email/otp", "phone/otp"], False),  # Only 2 out of 3
        (["email/otp", "phone/otp", "totp"], True),  # All 3
        (["email/otp"], False),  # Only 1 out of 3
    ],
)
def test_exchange_flow_requires_all_methods(
    exchange_flow: AuthFlow,
    amr: list[str],
    expected_completed: bool,
) -> None:
    """Test exchange flow that requires all methods."""
    next_step = validate_flow_completion(login_flow=exchange_flow, amr=amr)

    if expected_completed:
        assert next_step is None
    else:
        assert next_step == exchange_flow.steps[0]


def test_method_repetition_prevention(repetition_flow: AuthFlow) -> None:
    """Test that methods cannot be repeated across different steps."""
    # Use PHONE_OTP in first step
    amr = ["phone/otp"]
    next_step = validate_flow_completion(login_flow=repetition_flow, amr=amr)
    assert next_step == repetition_flow.steps[1]  # Second step needs completion

    # Now try to use PHONE_OTP again in second step (should not work)
    amr = ["phone/otp", "phone/otp"]
    next_step = validate_flow_completion(login_flow=repetition_flow, amr=amr)
    assert next_step == repetition_flow.steps[1]  # Second step still needs completion


def test_method_repetition_prevention_with_different_method(
    repetition_flow: AuthFlow,
) -> None:
    """Test that using different method in second step works."""
    # Use PHONE_OTP in first step, TOTP in second step
    amr = ["phone/otp", "totp"]
    next_step = validate_flow_completion(login_flow=repetition_flow, amr=amr)
    assert next_step is None  # All steps completed


@pytest.mark.parametrize(
    "amr,expected_step",
    [
        ([], 0),  # Empty amr
        (["unknown_method", "password"], None),  # Unknown method ignored
        (["password", "password"], None),  # Duplicate method ignored
    ],
)
def test_edge_cases_with_amr(
    simple_password_flow: AuthFlow,
    amr: list[str],
    expected_step: int | None,
) -> None:
    """Test edge cases with amr list."""
    next_step = validate_flow_completion(login_flow=simple_password_flow, amr=amr)

    if expected_step is None:
        assert next_step is None
    else:
        assert next_step == simple_password_flow.steps[expected_step]


@pytest.mark.parametrize(
    "amr,expected_step",
    [
        (["password"], 1),  # Only one method, need one more
        (["password", "totp"], None),  # Both methods used
    ],
)
def test_flow_with_required_num_greater_than_one(
    amr: list[str],
    expected_step: int | None,
) -> None:
    """Test flow where required_num is greater than 1."""
    flow = GOOGLE_FLOW

    next_step = validate_flow_completion(login_flow=flow, amr=amr)

    if expected_step is None:
        assert next_step is None
    else:
        assert next_step == flow.steps[expected_step]


@pytest.mark.parametrize(
    "amr,expected_step",
    [
        (["password"], 1),  # Step 1 completed
        (["password", "totp"], 2),  # Steps 1,2 completed
        (
            ["password", "totp", "phone/otp"],
            None,
        ),  # All completed
    ],
)
def test_complex_flow_with_multiple_steps(amr: list[str], expected_step: int) -> None:
    """Test a complex flow with multiple steps."""
    complex_flow = AuthFlow(
        allowed_identifiers=[AuthIdentifier.EMAIL],
        steps=[
            AuthStep(
                methods=[AuthSecret.PASSWORD, AuthSecret.MAGIC_LINK],
                required_num=1,
            ),
            AuthStep(methods=[AuthSecret.TOTP, AuthSecret.EMAIL_OTP], required_num=1),
            AuthStep(methods=[AuthSecret.PHONE_OTP], required_num=1),
        ],
    )

    next_step = validate_flow_completion(login_flow=complex_flow, amr=amr)

    if expected_step is None:
        assert next_step is None
    else:
        assert next_step == complex_flow.steps[expected_step]


def test_method_used_in_wrong_step(password_with_totp_flow: AuthFlow) -> None:
    """Test when a method is used but it's not available in the current step."""
    # Try to use TOTP in first step (only password is available)
    amr = ["totp"]
    next_step = validate_flow_completion(login_flow=password_with_totp_flow, amr=amr)
    assert (
        next_step == password_with_totp_flow.steps[0]
    )  # First step still needs completion


@pytest.mark.parametrize(
    "flow_name,amr,expected_result",
    [
        ("simple_password_flow", ["password"], None),
        ("simple_password_flow", [], 0),
        ("password_with_totp_flow", ["password", "totp"], None),
        ("password_with_totp_flow", ["password"], 1),
        (
            "exchange_flow",
            ["email/otp", "phone/otp", "totp"],
            None,
        ),
        ("exchange_flow", ["email/otp", "phone/otp"], 0),
    ],
)
def test_flow_completion_integration(
    request: pytest.FixtureRequest,
    flow_name: str,
    amr: list[str],
    expected_result: int | None,
) -> None:
    """Integration test for flow completion with different flows."""
    flow = request.getfixturevalue(flow_name)
    next_step = validate_flow_completion(login_flow=flow, amr=amr)

    if expected_result is None:
        assert next_step is None
    else:
        assert next_step == flow.steps[expected_result]
