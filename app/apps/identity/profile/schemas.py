"""Profile schemas."""

from fastapi_mongo_base.schemas import TenantUserEntitySchema
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
)

from utils.validators import validate_external_https_url


class ProfileDataCreateSchema(BaseModel):
    """Core profile fields only. Legacy ICE keys in Mongo are ignored on load."""

    model_config = ConfigDict(extra="ignore")

    first_name: str | None = Field(None, max_length=256)
    last_name: str | None = Field(None, max_length=256)
    avatar_url: str | None = Field(None, max_length=2048)
    meta_data: dict | None = None

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, value: str | None) -> str | None:
        """Prevent executable avatar URLs from reaching clients."""
        return validate_external_https_url(value)


class ProfileCreateSchema(BaseModel):
    """Profile create schema."""

    model_config = ConfigDict(extra="forbid")

    user_id: str | None = Field(default=None, max_length=128)
    meta_data: dict | None = None
    profile_data: ProfileDataCreateSchema = Field(
        default_factory=ProfileDataCreateSchema
    )


class ProfileDataUpdateSchema(BaseModel):
    """Editable profile fields for PATCH."""

    model_config = ConfigDict(extra="forbid")

    first_name: str | None = Field(None, max_length=256)
    last_name: str | None = Field(None, max_length=256)
    avatar_url: str | None = Field(None, max_length=2048)
    meta_data: dict | None = None

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, value: str | None) -> str | None:
        """Prevent executable avatar URLs from reaching clients."""
        return validate_external_https_url(value)


class ProfileUpdateSchema(BaseModel):
    """Profile update schema."""

    model_config = ConfigDict(extra="forbid")

    meta_data: dict | None = None
    profile_data: ProfileDataUpdateSchema | None = None


class ProfileDataSchema(ProfileDataCreateSchema):
    """Stored profile data schema."""


class ProfileSchema(TenantUserEntitySchema):
    """Profile schema."""

    profile_data: ProfileDataSchema = Field(default_factory=ProfileDataSchema)

    def __init__(self, **kwargs: object) -> None:
        """Initialize profile schema."""
        super().__init__(**kwargs)
        self.uid = self.user_id

    @computed_field
    @property
    def identifiers(self) -> list | None:
        """User identifiers."""
        return getattr(self, "_identifiers", None)


class ProfileResponseSchema(ProfileSchema):
    """Profile response schema."""

    user_data: dict | None = Field(
        default=None,
        description="The user data.",
        exclude_if=lambda value: value is None,
    )
