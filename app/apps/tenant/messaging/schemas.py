"""Messaging Tenant channel config schemas."""

from datetime import datetime

from fastapi_mongo_base.utils import timezone
from pydantic import BaseModel, Field


class TenantChannelConfig(BaseModel):
    """Tenant channel config."""

    tenant_id: str = Field(description="The tenant ID")
    channel_type: str = Field(description="The channel type")
    provider_name: str = Field(description="The provider name")
    provider_config: dict = Field(description="The provider config")
    is_active: bool = Field(default=True, description="Whether the channel is active")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.tz),
        description="The creation time",
    )
