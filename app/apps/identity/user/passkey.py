"""Passkey schemas."""

from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator


class AuthenticatorAttestationResponse(BaseModel):
    """WebAuthn credential response (registration or authentication)."""

    clientDataJSON: str = Field(..., description="Base64url-encoded client data")  # ruff:ignore[mixed-case-variable-in-class-scope]
    attestationObject: str | None = Field(  # ruff:ignore[mixed-case-variable-in-class-scope]
        None, description="Base64url-encoded attestation object (registration)"
    )
    authenticatorData: str | None = Field(  # ruff:ignore[mixed-case-variable-in-class-scope]
        None, description="Base64url-encoded authenticator data (authentication)"
    )
    signature: str | None = Field(None, description="Base64url-encoded signature")
    userHandle: str | None = Field(None, description="Base64url-encoded user handle")  # ruff:ignore[mixed-case-variable-in-class-scope]

    @model_validator(mode="after")
    def validate_response_shape(self) -> Self:
        """Registration: attestationObject; login: authenticatorData+signature."""
        if self.attestationObject:
            return self
        if self.authenticatorData and self.signature:
            return self
        raise ValueError(
            "Provide attestationObject for registration or "
            "authenticatorData+signature for authentication"
        )


class PasskeyAssertion(BaseModel):
    """SimpleWebAuthn credential JSON (registration or authentication)."""

    type: Literal["public-key"] = "public-key"
    id: str = Field(..., description="Base64url-encoded credential ID")
    rawId: str = Field(..., description="Base64url-encoded raw credential ID")  # ruff:ignore[mixed-case-variable-in-class-scope]
    authenticatorAttachment: Literal["platform", "cross-platform"] | None = (  # ruff:ignore[mixed-case-variable-in-class-scope]
        Field(None, description="Authenticator attachment type")
    )
    clientExtensionResults: dict | None = Field(  # ruff:ignore[mixed-case-variable-in-class-scope]
        None, description="Client extension results"
    )
    response: AuthenticatorAttestationResponse = Field(
        ..., description="Authenticator attestation/assertion response"
    )
