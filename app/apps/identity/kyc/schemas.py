"""KYC schemas."""

from datetime import date, datetime
from enum import StrEnum

from fastapi_mongo_base.schemas import TenantUserEntitySchema
from pydantic import BaseModel, Field, field_validator
from usso.user import TokenType

from apps.identity.auth.enums import LoginStatus


class KYCStatus(StrEnum):
    """KYC status enumeration."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class KYCCreateSchema(BaseModel):
    """KYC create schema."""

    national_code: str = Field(..., description="The national code.")
    birth_date: date = Field(
        ...,
        description="The birth date.",
        examples=[date(1990, 1, 19)],
    )
    return_url: str | None = Field(None, description="The return URL.")

    @field_validator("national_code")
    @classmethod
    def validate_national_code(cls, value: str) -> str:
        """Ensure national_code is valid."""
        from utils import validators

        if not validators.validate_national_code(value):
            raise ValueError(f"Invalid national code: {value}")
        return value

    @property
    def birth_date_shamsi(self) -> str:
        """The birth date as a Shamsi yyyy/MM/dd string."""
        from utils.validators import validate_date_for_sahmsi

        return validate_date_for_sahmsi(self.birth_date)


class KYCSchema(TenantUserEntitySchema, KYCCreateSchema):
    """KYC schema."""

    kyc_id: str | None = None
    status: KYCStatus = Field(
        default=KYCStatus.PENDING, description="The status of the KYC."
    )
    civil_data: dict | None = None
    # When the registries confirmed the data (civil = ثبت احوال, phone = شاهکار).
    civil_verified_at: datetime | None = None
    phone_verified_at: datetime | None = None


class CreateKycResponse(BaseModel):
    """KYC creation response with status and optional auth tokens."""

    status: LoginStatus = LoginStatus.FAILED
    kyc: KYCSchema
    tokens: dict[TokenType, str] | None = Field(
        default=None,
        description="Tokens for the user",
    )
