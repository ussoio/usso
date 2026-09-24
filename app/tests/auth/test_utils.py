"""Tests for email and username validation utilities."""

import email_validator
import pytest
from usso.utils.validators import validate_email, validate_username

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def syntax_only_email_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep validation tests independent from external DNS latency."""
    validate = email_validator.validate_email

    def validate_without_deliverability(email: str, **kwargs: object) -> object:
        kwargs["check_deliverability"] = False
        return validate(email, **kwargs)

    monkeypatch.setattr(
        email_validator,
        "validate_email",
        validate_without_deliverability,
    )


# Test email validation utility functions
def test_validate_email_syntax_only(syntax_only_email_validation: None) -> None:
    """Test email validation with syntax-only validation (no DNS check)."""
    # Valid email formats
    assert validate_email("test@example.com") == (True, None, "test@example.com")
    assert validate_email("user.name+tag@domain.co.uk") == (
        True,
        None,
        "user.name+tag@domain.co.uk",
    )
    assert validate_email("test@uln.me") == (True, None, "test@uln.me")

    # Invalid email formats
    assert validate_email("invalid-email") == (False, "Email is invalid", None)
    assert validate_email("@domain.com") == (False, "Email is invalid", None)
    assert validate_email("user@") == (False, "Email is invalid", None)
    assert validate_email("user@.com") == (False, "Email is invalid", None)


def test_validate_email_gmail_normalization(syntax_only_email_validation: None) -> None:
    """Test Gmail email normalization (removing dots and plus tags)."""
    # Gmail normalization
    assert validate_email("test@gmail.com") == (True, None, "test@gmail.com")
    assert validate_email("t.e.s.t@gmail.com") == (True, None, "test@gmail.com")
    assert validate_email("test+tag@gmail.com") == (True, None, "test@gmail.com")
    assert validate_email("t.e.s.t+tag@gmail.com") == (True, None, "test@gmail.com")


@pytest.mark.parametrize(
    "test, valid",
    {
        "john": True,
        "JoHn": True,
        "jo": False,
        "_a1": True,
        "a__b": False,
        "a._-b": False,
        "a.-b": False,
        "a..b": False,
        "a-": False,
        "admin": False,
        "__admin__": False,
        "ad-min": True,
        "b.a.dword": True,
        "Hitler": False,
        "user$name": False,
        "glona_zi": False,
        "a_b_c": True,
        "_ok_": False,
        "____ok": False,
        "ok____": False,
        "päul": False,
        "a__b__c": False,
        "a.-.-b": False,
        "a._.b": False,
        "abc": True,
        "a_b-": False,
        "a_b_.": False,
    }.items(),
)
def test_validate_username(test: str, valid: bool) -> None:
    """Test username validation with various inputs."""
    check, _, _ = validate_username(test)
    assert check == valid
