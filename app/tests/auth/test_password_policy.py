"""Tests for password policy validation utility."""

import pytest

from apps.identity.auth.pass_validator import validate_password_policy
from apps.identity.auth.schemas import PasswordPolicyResult
from apps.tenant.config import AuthenticationConfig

pytestmark = pytest.mark.timeout(0.5, func_only=True)


@pytest.fixture
def default_config() -> AuthenticationConfig:
    """Tenant config with all password requirements enabled (defaults)."""
    return AuthenticationConfig()


@pytest.fixture
def relaxed_config() -> AuthenticationConfig:
    """Tenant config with all extra requirements disabled."""
    return AuthenticationConfig(
        password_min_length=4,
        password_require_special=False,
        password_require_numbers=False,
        password_require_uppercase=False,
        password_require_lowercase=False,
    )


def test_valid_password_all_rules(default_config: AuthenticationConfig) -> None:
    """Test that a password meeting all rules passes validation."""
    result = validate_password_policy("Str0ng!Pass", default_config)
    assert result.is_valid is True
    assert result.unmet_requirements == []


def test_too_short(default_config: AuthenticationConfig) -> None:
    """Test that a too-short password fails validation."""
    result = validate_password_policy("A1!a", default_config)
    assert result.is_valid is False
    assert any("حداقل" in r for r in result.unmet_requirements)


def test_missing_uppercase(default_config: AuthenticationConfig) -> None:
    """Test that a password without uppercase fails validation."""
    result = validate_password_policy("str0ng!pass", default_config)
    assert result.is_valid is False
    assert "رمز عبور باید شامل حروف بزرگ باشد" in result.unmet_requirements


def test_missing_lowercase(default_config: AuthenticationConfig) -> None:
    """Test that a password without lowercase fails validation."""
    result = validate_password_policy("STR0NG!PASS", default_config)
    assert result.is_valid is False
    assert "رمز عبور باید شامل حروف کوچک باشد" in result.unmet_requirements


def test_missing_numbers(default_config: AuthenticationConfig) -> None:
    """Test that a password without numbers fails validation."""
    result = validate_password_policy("Strong!Pass", default_config)
    assert result.is_valid is False
    assert "رمز عبور باید شامل اعداد باشد" in result.unmet_requirements


def test_missing_special_chars(default_config: AuthenticationConfig) -> None:
    """Test that a password without special characters fails validation."""
    result = validate_password_policy("Str0ngPass1", default_config)
    assert result.is_valid is False
    assert "رمز عبور باید شامل کاراکترهای خاص باشد" in result.unmet_requirements


def test_multiple_unmet_requirements(default_config: AuthenticationConfig) -> None:
    """Test that a very weak password reports multiple unmet requirements."""
    result = validate_password_policy("short", default_config)
    assert result.is_valid is False
    assert len(result.unmet_requirements) >= 3


def test_relaxed_config_accepts_simple_password(
    relaxed_config: AuthenticationConfig,
) -> None:
    """Test that a relaxed config accepts simple passwords."""
    result = validate_password_policy("abcd", relaxed_config)
    assert result.is_valid is True
    assert result.unmet_requirements == []


def test_relaxed_config_still_checks_min_length(
    relaxed_config: AuthenticationConfig,
) -> None:
    """Test that relaxed config still enforces minimum length."""
    result = validate_password_policy("abc", relaxed_config)
    assert result.is_valid is False
    assert any("حداقل" in r for r in result.unmet_requirements)


def test_returns_password_policy_result_type(
    default_config: AuthenticationConfig,
) -> None:
    """Test that validation returns a PasswordPolicyResult instance."""
    result = validate_password_policy("Str0ng!Pass", default_config)
    assert isinstance(result, PasswordPolicyResult)


def test_min_length_message_includes_configured_length() -> None:
    """Test that min-length error includes the configured value."""
    config = AuthenticationConfig(password_min_length=12)
    result = validate_password_policy("Sh0rt!", config)
    assert any("12" in r for r in result.unmet_requirements)
