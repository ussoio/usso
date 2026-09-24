"""
Authentication schemas.

This module contains the schemas for the authentication endpoints.
"""

from pydantic import BaseModel, EmailStr

from .enums import AuthIdentifier, AuthSecret
from .schemas import LoginRequest


class BaseLoginBody(BaseModel):
    """Base login body."""

    @property
    def login_request(self) -> LoginRequest:
        """The login request."""
        return LoginRequest(
            type=self.type,
            identifier=self.identifier,
            method=self.method,
            secret=self.secret,
        )


class EmailPasswordLogin(BaseLoginBody):
    """Email password login."""

    email: EmailStr
    password: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.EMAIL

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.email

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.PASSWORD

    @property
    def secret(self) -> str:
        """The password secret."""
        return self.password


class EmailOtpLogin(BaseLoginBody):
    """Email OTP login."""

    email: EmailStr
    otp: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.EMAIL

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.email

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.EMAIL_OTP

    @property
    def secret(self) -> str:
        """The OTP secret."""
        return self.otp


class PhoneOtpLogin(BaseLoginBody):
    """Phone OTP login."""

    phone: str
    otp: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.PHONE

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.phone

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.PHONE_OTP

    @property
    def secret(self) -> str:
        """The OTP secret."""
        return self.otp


class PhonePasswordLogin(BaseLoginBody):
    """Phone password login."""

    phone: str
    password: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.PHONE

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.phone

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.PASSWORD

    @property
    def secret(self) -> str:
        """The password secret."""
        return self.password


class UsernamePasswordLogin(BaseLoginBody):
    """Username password login."""

    username: str
    password: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.USERNAME

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.username

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.PASSWORD

    @property
    def secret(self) -> str:
        """The password secret."""
        return self.password


class UsernameOtpLogin(BaseLoginBody):
    """Username OTP login."""

    username: str
    otp: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.USERNAME

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.username

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.PHONE_OTP

    @property
    def secret(self) -> str:
        """The OTP secret."""
        return self.otp


class ClientIDSecretLogin(BaseLoginBody):
    """Client id / client secret login."""

    client_id: str
    client_secret: str

    @property
    def type(self) -> AuthIdentifier:
        """The type."""
        return AuthIdentifier.CLIENT_ID

    @property
    def identifier(self) -> AuthIdentifier:
        """The identifier."""
        return self.client_id

    @property
    def method(self) -> AuthSecret:
        """The method."""
        return AuthSecret.CLIENT_SECRET

    @property
    def secret(self) -> str:
        """The client secret."""
        return self.client_secret


LoginBody = (
    EmailPasswordLogin
    | EmailOtpLogin
    | PhonePasswordLogin
    | PhoneOtpLogin
    | UsernamePasswordLogin
    | UsernameOtpLogin
    | ClientIDSecretLogin
)
