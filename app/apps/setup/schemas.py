"""Setup schemas."""

from pydantic import BaseModel, ConfigDict, Field


class EmailSettings(BaseModel):
    """Email settings."""

    model_config = ConfigDict(extra="forbid")

    host: str
    port: int
    username: str
    password: str
    sender: str
    use_tls: bool = False
    use_ssl: bool = False
    verify_ssl: bool = True
    timeout: int = 30


class OAuthSettings(BaseModel):
    """OAuth settings."""

    model_config = ConfigDict(extra="forbid")

    name: str
    discovery_url: str
    client_id: str
    client_secret: str
    scopes: list[str] = ["openid", "profile", "email"]


class AdminSettings(BaseModel):
    """Admin settings."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=100)
    username: str
    email: str
    password: str = Field(..., min_length=8, max_length=1024)
    phone: str | None = None


class SetupRequest(BaseModel):
    """Setup request."""

    model_config = ConfigDict(extra="forbid")

    name: str
    domains: list[str]
    kavenegar_api: str | None = None
    email: EmailSettings | None = None
    oauth: list[OAuthSettings] | None = None
    admin_account: AdminSettings
