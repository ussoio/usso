"""Authentication schemas."""

from collections.abc import Callable, Iterable
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from usso.user import TokenType, UserData

from ..session.schemas import SessionType
from ..user.models import User
from ..user.passkey import PasskeyAssertion
from .enums import AuthIdentifier, AuthSecret, AuthStep, LoginStatus, OTPDeliveryStatus

__all__ = ["PasskeyAssertion"]


class PayloadData(UserData):
    """Payload data."""

    def __init__(
        self,
        *,
        jti: str | None = None,
        token_type: TokenType | None = None,
        iss: str | None = None,
        aud: str | None = None,
        iat: int | None = None,
        nbf: int | None = None,
        exp: int | None = None,
        sub: str | None = None,
        tenant_id: str | None = None,
        session_id: str | None = None,
        workspace_id: str | None = None,
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
        amr: list[str] | None = None,
        acr: str | None = None,
        signing_level: str | None = None,
        claims: dict | None = None,
        **kwargs: object,
    ) -> None:
        """
        Initialize the payload data.

        Args:
            jti: The JWT ID
            token_type: The token type
            iss: The issuer
            aud: The audience
            iat: The issued at
            nbf: The not before
            exp: The expires at
            sub: The subject
            tenant_id: The tenant ID
            session_id: The session ID
            workspace_id: The workspace ID
            roles: The roles
            scopes: The scopes
            amr: The authentication methods
            acr: The authentication context class reference
            signing_level: The signing level
            claims: The claims
            **kwargs: Additional keyword arguments
        Returns:
            None.

        """
        super(UserData, self).__init__(
            jti=jti,
            token_type=token_type,
            iss=iss,
            aud=aud,
            iat=iat,
            nbf=nbf,
            exp=exp,
            sub=sub,
            tenant_id=tenant_id,
            session_id=session_id,
            workspace_id=workspace_id,
            roles=roles,
            scopes=scopes,
            amr=amr,
            acr=acr,
            signing_level=signing_level,
            claims=claims,
            **kwargs,
        )

    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] | str = "python",
        include: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
        context: object | None = None,
        by_alias: bool | None = None,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        round_trip: bool = False,
        warnings: bool | Literal["none", "warn", "error"] = True,
        fallback: Callable[[object], object] | None = None,
        serialize_as_any: bool = False,
    ) -> dict:
        res = super().model_dump(
            mode=mode,
            include=include,
            exclude=exclude,
            context=context,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            round_trip=round_trip,
            warnings=warnings,
            fallback=fallback,
            serialize_as_any=serialize_as_any,
        )
        if exclude is None:
            res.pop("claims", None)
            return (self.claims or {}) | res
        return res

    @property
    def token(self) -> str | None:
        return getattr(self, "_token", None)

    @token.setter
    def token(self, value: str) -> None:
        self._token = value


class Identifier(BaseModel):
    type: AuthIdentifier | None = Field(
        default=None,
        description="Identifier type: email, phone, username, etc.",
    )
    identifier: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Identifier value (email, phone, username, etc.)",
    )

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        validator = self.type.get_identifier_validator()
        is_valid, error, canonical_identifier = validator(self.identifier)
        if not is_valid:
            raise ValueError(error)
        self.identifier = canonical_identifier
        return self


class Secret(BaseModel):
    method: AuthSecret | None = Field(
        default=None,
        description="Auth method: password, otp, totp, etc.",
    )
    secret: str | None = Field(
        default=None,
        min_length=1,
        max_length=16_384,
        description="Secret value (password, OTP, etc.)",
    )


class LoginRequest(Identifier, Secret):
    referral_code: str | None = Field(
        default=None,
        description=(
            "Invitation code or invite link (query/path). "
            "Required when tenant registration.invite_only is enabled."
        ),
    )

    @field_validator("referral_code", mode="before")
    @classmethod
    def normalize_referral_code(cls, value: object) -> str | None:
        """Accept bare codes or invite URLs and extract the code."""
        if value is None:
            return None
        from apps.identity.referral.services import extract_referral_code

        return extract_referral_code(str(value))


class SecureTokenRequest(Identifier, Secret):
    """Step-up credentials; registration and referral fields are forbidden."""

    model_config = ConfigDict(extra="forbid")


class LoginResponse(PayloadData):
    next_step: AuthStep | None = None
    status: LoginStatus = LoginStatus.FAILED

    tokens: dict[TokenType, str] | None = Field(
        default=None,
        description="Tokens for the user",
    )


class WorkspaceLoginRequest(BaseModel):
    """Request body for login into another workspace (switch workspace)."""

    workspace_id: str = Field(..., description="Workspace ID to switch to")
    refresh_token: str | None = Field(
        default=None,
        description="Refresh token (optional if sent via cookie)",
    )


class RefreshResponse(BaseModel):
    status: LoginStatus = LoginStatus.REFRESHED
    tokens: dict[TokenType, str] | None = Field(
        default=None,
        description="Tokens for the user",
    )
    expires_in: int | None = None

    def model_dump(self, **kwargs: object) -> dict:
        kwargs.setdefault("exclude_none", True)
        res = super().model_dump(**kwargs)
        return res


class AccountSwitchRequest(BaseModel):
    """Select one account already linked to this browser."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(..., min_length=1, max_length=128)


class BrowserAccountResponse(BaseModel):
    """Safe account information returned to the account chooser."""

    user_id: str
    name: str | None = None
    avatar_url: str | None = None
    session_type: SessionType
    workspace_id: str | None = None
    active: bool = False


class BrowserAccountListResponse(BaseModel):
    """Accounts with live sessions in the current browser account set."""

    accounts: list[BrowserAccountResponse] = Field(default_factory=list)
    active_user_id: str | None = None


class OTPRequest(Identifier):
    channel_type: str = Field(
        default="sms",
        description="Channel type: sms, email, bale, etc",
    )

    @model_validator(mode="before")
    @classmethod
    def check_channel_type(cls, values: dict) -> dict:
        if values.get("channel_type"):
            return values

        match values.get("type"):
            case AuthIdentifier.EMAIL:
                values["channel_type"] = "email"
            case AuthIdentifier.PHONE:
                values["channel_type"] = values.get("channel_type", "sms")
        return values

    @field_validator("channel_type")
    @classmethod
    def validate_channel_type(cls, v: str) -> str:
        from apps.tenant.messaging.channels.base import AbstractChannel

        if not AbstractChannel.validate_type(typ=v):
            raise ValueError(f"Invalid channel type: {v}")
        return v

    def get_channel(self, tenant: object) -> object:
        from apps.tenant.messaging.channels.base import AbstractChannel

        return AbstractChannel.create_channel(typ=self.channel_type, tenant=tenant)


class MagicLinkRequest(Identifier):
    pass
    # redirect_url: str | None = None  # ruff:ignore[commented-out-code]


class RefreshRequest(BaseModel):
    refresh_token: str


class QRCodeResponse(BaseModel):
    """Desktop QR session bootstrap."""

    qr_token: str
    expires_in: int = 120
    qr_payload: str


class QRApproveRequest(BaseModel):
    """Phone-side approve/deny of a pending QR session."""

    qr_token: str
    approve: bool = True


class QRStatusResponse(BaseModel):
    """Desktop poll status for a QR session."""

    status: str
    expires_in: int | None = None
    user_id: str | None = None


class ResetPasswordRequest(BaseModel):
    """Set/change password; requires a valid secure session token."""

    new_password: str = Field(..., min_length=1, max_length=1024)


class PasswordPolicyResult(BaseModel):
    """Result of password policy validation."""

    is_valid: bool
    unmet_requirements: list[str] = Field(default_factory=list)


class LoginAttemptResponse(BaseModel):
    """Response for POST /auth/login-attempts."""

    status: LoginStatus = LoginStatus.CHALLENGE_REQUIRED
    next_step: AuthStep | None = None
    otp_delivery: dict[str, OTPDeliveryStatus] = Field(default_factory=dict)

    tokens: dict[TokenType, str] | None = Field(
        default=None,
        description="Tokens (temporary token set here)",
    )


class LoginAttemptResult(BaseModel):
    """Internal result from resolve_login_attempt service."""

    status: LoginStatus
    user: User | None = None
    next_step: AuthStep | None = None
    otp_delivery: dict[str, OTPDeliveryStatus] = Field(default_factory=dict)
    error: str | None = None
    message: str | None = None


class LoginFlowResult(BaseModel):
    status: LoginStatus
    user: User | None = None
    amr: list[str] = []
    next_step: AuthStep | None = None
    message: str | None = None
    error: str | None = None


class VerifyTokenRequest(BaseModel):
    token: str
    token_type: TokenType = TokenType.ACCESS
