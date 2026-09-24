"""Referral schemas."""

from datetime import datetime

from fastapi_mongo_base.schemas import TenantUserEntitySchema
from pydantic import BaseModel, ConfigDict, Field

from utils import texttools


class ReferralCodeCreateSchema(BaseModel):
    """Caller-editable referral fields; counters and status are server-owned."""

    model_config = ConfigDict(extra="forbid")

    user_id: str | None = Field(default=None, min_length=1, max_length=128)
    code: str = Field(
        default_factory=lambda: texttools.generate_human_readable_code(6),
        min_length=4,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    expires_at: datetime | None = None
    max_usage: int | None = Field(default=None, ge=1, le=1_000_000)


class ReferralCodeSchema(TenantUserEntitySchema):
    """Referral code schema."""

    code: str = Field(default_factory=lambda: texttools.generate_human_readable_code(6))
    expires_at: datetime | None = None
    is_active: bool = True
    usage_count: int = 0
    max_usage: int | None = None
