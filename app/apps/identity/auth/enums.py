"""Authentication enums."""

from collections.abc import Callable
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator
from usso.utils import validators


def validate_email_identifier(email: str) -> tuple[bool, str | None, str | None]:
    """Validate and canonicalize an email address without a DNS lookup."""
    import email_validator

    try:
        validated = email_validator.validate_email(email, check_deliverability=False)
    except email_validator.EmailNotValidError:
        return False, "Email is invalid", None

    local_part, _, domain = validated.normalized.partition("@")
    if domain.lower() == "gmail.com":
        local_part = local_part.split("+", maxsplit=1)[0].replace(".", "")
    return True, None, f"{local_part}@{domain}"


class AuthIdentifier(StrEnum):
    """
    Authentication identifiers.

    These are the ways a user or application can be identified in the system.
    Each identifier type represents a different way to look up an entity.
    """

    # User identifiers
    EMAIL = "email"  # Email address
    PHONE = "phone"  # Phone number
    USERNAME = "username"  # Username
    TELEGRAM_ID = "telegram_id"  # Telegram user ID
    BALE_ID = "bale_id"  # Bale messenger user ID
    PASSKEY_ID = "passkey_id"  # Passkey ID (WebAuthn/FIDO2)
    QR_SESSION = "qr_session"  # like WhatsApp Web style QR login
    NATIONAL_ID = "national_id"  # National ID

    # Application identifiers
    CLIENT_ID = "client_id"  # OIDC client ID
    SERVICE_ID = "service_id"  # Service account ID

    def get_identifier_validator(self) -> Callable[[str], tuple[bool, str, str]]:
        """Get the validator for this identifier type."""
        return {
            AuthIdentifier.EMAIL: validate_email_identifier,
            AuthIdentifier.PHONE: lambda x: validators.validate_phone(x, "IR"),
            AuthIdentifier.USERNAME: validators.validate_username,
            AuthIdentifier.TELEGRAM_ID: validators.validate_telegram_id,
            # Bale user ids are the same numeric shape as Telegram ids.
            AuthIdentifier.BALE_ID: validators.validate_telegram_id,
        }.get(self, lambda s: (True, None, s))

    @property
    def fa_name(self) -> str:
        """Farsi name for this identifier type."""
        return {
            AuthIdentifier.EMAIL: "ایمیل",
            AuthIdentifier.PHONE: "شماره تلفن",
            AuthIdentifier.USERNAME: "نام کاربری",
            AuthIdentifier.TELEGRAM_ID: "شناسه تلگرام",
            AuthIdentifier.BALE_ID: "شناسه بله",
            AuthIdentifier.PASSKEY_ID: "شناسه پسورد",
            AuthIdentifier.QR_SESSION: "شناسه QR",
            AuthIdentifier.NATIONAL_ID: "شناسه ملی",
            AuthIdentifier.CLIENT_ID: "شناسه مشتری",
            AuthIdentifier.SERVICE_ID: "شناسه سرویس",
        }.get(self, self.value)


class AuthSecret(StrEnum):
    """
    Authentication secrets.

    These are the methods used to verify the identity of a user.
    Each secret type represents a different way to prove identity.
    """

    # Password-based authentication
    PASSWORD = "password"  # Traditional password

    # One-time password methods
    TOTP = "totp"  # Time-based OTP (Authenticator apps)
    EMAIL_OTP = "email/otp"  # Email OTP
    PHONE_OTP = "phone/otp"  # SMS OTP

    # Backup codes for account recovery
    BACKUP_CODES = "backup_codes"

    # Modern authentication / Passwordless
    WEBAUTHN = "webauthn"  # Passkeys/FIDO2
    MAGIC_LINK = "magic_link"  # Email magic link

    # OAuth authentication
    OAUTH = "oauth"  # OAuth access token
    ID_TOKEN = "id_token"  # OIDC ID token
    CLIENT_SECRET = "client_secret"  # OIDC client secret

    # Telegram authentication
    TELEGRAM_TOKEN = "telegram_token"  # Telegram bot token

    @classmethod
    def get_identifier_type(cls, method: "AuthSecret") -> AuthIdentifier | None:
        """Get the corresponding identifier type for an authentication method."""
        method_to_identifier_map: dict[AuthSecret, AuthIdentifier] = {
            cls.EMAIL_OTP: AuthIdentifier.EMAIL,
            cls.PHONE_OTP: AuthIdentifier.PHONE,
            cls.MAGIC_LINK: AuthIdentifier.EMAIL,
            cls.WEBAUTHN: AuthIdentifier.PASSKEY_ID,
            cls.OAUTH: AuthIdentifier.EMAIL,
            cls.TELEGRAM_TOKEN: AuthIdentifier.TELEGRAM_ID,
        }
        return method_to_identifier_map.get(method)


class AuthStep(BaseModel):
    """
    A single step in the login flow.

    Can have multiple parallel authentication methods.
    """

    methods: list[AuthSecret] = Field(
        description="List of authentication methods that can be used in this step"
    )
    required_num: int = Field(
        default=1,
        description="Number of methods that must be passed in this step",
    )

    @model_validator(mode="after")
    def validate_step(self) -> Self:
        """Validate that the step is properly configured."""
        if not self.methods:
            raise ValueError("Step must have at least one authentication method")
        if self.required_num > len(self.methods):
            raise ValueError(
                f"Step requires {self.required_num} methods "
                "but only has {len(self.methods)} methods"
            )
        if len(self.methods) != len(set(self.methods)):
            raise ValueError("Step must have unique authentication methods")
        return self


class AuthFlow(BaseModel):
    """
    Configuration for a authentication flow.

    This model defines a sequence of authentication steps, where each step
    can have multiple parallel methods. The flow starts with a list of allowed
    identifiers that can be used to identify the user.

    Example:
    AuthFlow(
        allowed_identifiers=[AuthIdentifier.EMAIL, AuthIdentifier.PHONE],
        steps=[
            LoginStep(
                methods=[AuthSecret.PASSWORD],
                required_num=1
            ),
            LoginStep(
                methods=[AuthSecret.TOTP, AuthSecret.EMAIL_OTP],
                required_num=1
            )
        ]
    )

    """

    allowed_identifiers: list[AuthIdentifier] = Field(
        description="List of allowed identifier types for this flow"
    )
    steps: list[AuthStep] = Field(
        default_factory=list,
        description="List of authentication steps in sequence",
    )

    @field_validator("steps")
    @classmethod
    def validate_steps(cls, steps: list[AuthStep]) -> list[AuthStep]:
        """Validate that the steps are properly configured."""
        if not steps:
            raise ValueError("Flow must have at least one step")
        return steps

    @field_validator("allowed_identifiers")
    @classmethod
    def validate_allowed_identifiers(
        cls,
        allowed_identifiers: list[AuthIdentifier],
    ) -> list[AuthIdentifier]:
        """Validate that the allowed identifiers are properly configured."""
        if not allowed_identifiers:
            raise ValueError("Flow must have at least one allowed identifier")
        return allowed_identifiers


# Example authentication flows
SIMPLE_PASSWORD = AuthFlow(
    allowed_identifiers=[
        AuthIdentifier.EMAIL,
        AuthIdentifier.USERNAME,
        AuthIdentifier.PHONE,
    ],
    steps=[
        AuthStep(
            methods=[AuthSecret.PASSWORD],
            required_num=1,
        )
    ],
)

PASSWORD_WITH_TOTP = AuthFlow(
    allowed_identifiers=[AuthIdentifier.EMAIL],
    steps=[
        # Step 1: Password
        AuthStep(
            methods=[AuthSecret.PASSWORD],
            required_num=1,
        ),
        # Step 2: Any OTP method
        AuthStep(
            methods=[
                AuthSecret.TOTP,
                AuthSecret.EMAIL_OTP,
                AuthSecret.PHONE_OTP,
            ],
            required_num=1,
        ),
    ],
)

PASSWORD_OR_OTP = AuthFlow(
    allowed_identifiers=[
        AuthIdentifier.EMAIL,
        AuthIdentifier.USERNAME,
        AuthIdentifier.PHONE,
    ],
    steps=[
        # Step 1: Password
        AuthStep(
            methods=[
                AuthSecret.PASSWORD,
                AuthSecret.EMAIL_OTP,
                AuthSecret.PHONE_OTP,
            ],
            required_num=1,
        ),
    ],
)

PASSWORDLESS_FLOW = AuthFlow(
    allowed_identifiers=[
        AuthIdentifier.PASSKEY_ID,
        AuthIdentifier.EMAIL,
    ],
    steps=[
        # Step 1: Any passwordless method
        AuthStep(
            methods=[
                AuthSecret.MAGIC_LINK,
                AuthSecret.EMAIL_OTP,
                AuthSecret.WEBAUTHN,
            ],
            required_num=1,
        )
    ],
)

SIMPLE_PASSWORD_OR_PASSWORDLESS_FLOW = AuthFlow(
    allowed_identifiers=[AuthIdentifier.EMAIL],
    steps=[
        AuthStep(
            methods=[
                AuthSecret.PASSWORD,
                AuthSecret.MAGIC_LINK,
                AuthSecret.WEBAUTHN,
            ],
            required_num=1,
        )
    ],
)

# a flow like google. after user or email identifier,
# and password, it requires a totp or phone otp or passkey
GOOGLE_FLOW = AuthFlow(
    allowed_identifiers=[AuthIdentifier.EMAIL, AuthIdentifier.USERNAME],
    steps=[
        AuthStep(
            methods=[
                AuthSecret.PASSWORD,
            ],
            required_num=1,
        ),
        AuthStep(
            methods=[
                AuthSecret.TOTP,
                AuthSecret.PHONE_OTP,
                AuthSecret.WEBAUTHN,
            ],
            required_num=1,
        ),
    ],
)

# exchange flow, after login it require all of email otp and phone otp and totp
EXCHANGE_TRANSACTION_FLOW = AuthFlow(
    allowed_identifiers=[AuthIdentifier.EMAIL],
    steps=[
        AuthStep(
            methods=[
                AuthSecret.EMAIL_OTP,
                AuthSecret.PHONE_OTP,
                AuthSecret.TOTP,
            ],
            required_num=3,
        ),
    ],
)


class OTPDeliveryStatus(StrEnum):
    """OTP delivery status for login attempt responses."""

    SENT = "sent"
    REQUESTABLE = "requestable"
    UNAVAILABLE = "unavailable"


class LoginStatus(StrEnum):
    """Login status enumeration."""

    CHALLENGE_REQUIRED = "challenge_required"
    REGISTRATION_REQUIRED = "registration_required"
    VERIFICATION_REQUIRED = "verification_required"
    MFA_REQUIRED = "mfa_required"
    COMPLETED = "completed"
    FAILED = "failed"

    REFRESHED = "refreshed"
