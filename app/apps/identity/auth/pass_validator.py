"""Authentication utility functions."""

import re

from apps.tenant.config import AuthenticationConfig

from .schemas import PasswordPolicyResult


def validate_password_policy(
    password: str,
    tenant_config: AuthenticationConfig,
) -> PasswordPolicyResult:
    """
    Validate a password against the tenant's password policy.

    Args:
        password: The password to validate.
        tenant_config: The tenant's authentication configuration
            containing password policy rules.

    Returns:
        PasswordPolicyResult with is_valid and unmet_requirements (Farsi).

    """
    unmet: list[str] = []

    if len(password) < tenant_config.password_min_length:
        unmet.append(
            f"رمز عبور باید حداقل {tenant_config.password_min_length} کاراکتر باشد"
        )

    if tenant_config.password_require_uppercase and not re.search(r"[A-Z]", password):
        unmet.append("رمز عبور باید شامل حروف بزرگ باشد")

    if tenant_config.password_require_lowercase and not re.search(r"[a-z]", password):
        unmet.append("رمز عبور باید شامل حروف کوچک باشد")

    if tenant_config.password_require_numbers and not re.search(r"\d", password):
        unmet.append("رمز عبور باید شامل اعداد باشد")

    if tenant_config.password_require_special and not re.search(
        r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password
    ):
        unmet.append("رمز عبور باید شامل کاراکترهای خاص باشد")

    return PasswordPolicyResult(
        is_valid=len(unmet) == 0,
        unmet_requirements=unmet,
    )
