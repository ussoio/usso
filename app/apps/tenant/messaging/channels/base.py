"""Abstract channel base class."""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Self

from pydantic import BaseModel

from server.exceptions import BadRequestError

from ...models import Tenant


class ChannelType(StrEnum):
    """Channel type."""

    sms = "sms"
    bale = "bale"
    email = "email"


class AbstractChannel(ABC):
    """Abstract channel."""

    supports_phone: bool = False

    @property
    @abstractmethod
    def ConfigType(self) -> type[BaseModel]:  # ruff:ignore[invalid-function-name]
        """The type of the config for the channel."""

    def __init__(self, *, tenant: Tenant, **kwargs: object) -> None:
        """Initialize the channel."""
        channel_config = tenant.secrets.channel_configs.get(self.channel_type)
        if not channel_config:
            detail = f"Channel config not found for {self.channel_type}"
            raise BadRequestError(
                error_code="channel_not_found",
                detail=detail,
                message={"en": detail, "fa": "تنظیمات ارسال پیام پیدا نشد."},
            )
        config = channel_config.provider_config
        if isinstance(config, self.ConfigType):
            self.config = config
        elif isinstance(config, dict):
            self.config = self.ConfigType.model_validate(config)
        else:
            raise TypeError("Invalid SMS config")

    @property
    @abstractmethod
    def channel_type(self) -> ChannelType:
        """The type of the channel."""

    @abstractmethod
    def send(
        self, *, to: str, message: str, subject: str | None = None, **kwargs: object
    ) -> None:
        """Send a message to the channel."""

    async def asend(
        self, *, to: str, message: str, subject: str | None = None, **kwargs: object
    ) -> None:
        """Send a message to the channel."""
        return self.send(to=to, message=message, subject=subject, **kwargs)

    @classmethod
    def _load_channel_subclasses(cls) -> None:
        """Import concrete channels so they register via ``__subclasses__()``."""
        import apps.tenant.messaging.channels  # ruff: ignore[unused-import]

    @classmethod
    def create_channel(cls, *, typ: str, tenant: Tenant, **kwargs: object) -> Self:
        """Create a channel for the tenant."""
        cls._load_channel_subclasses()
        for sub_class in cls.__subclasses__():
            if sub_class.channel_type == typ:
                return sub_class(tenant=tenant, **kwargs)
        raise ValueError(f"Channel type {typ} not found")

    @classmethod
    def validate_type(cls, *, typ: str) -> Self:
        """Create a channel for the tenant."""
        cls._load_channel_subclasses()
        return any(sub_class.channel_type == typ for sub_class in cls.__subclasses__())

    @classmethod
    def phone_channel_types(cls) -> set[str]:
        """Return channel_type values of subclasses that support phone."""
        cls._load_channel_subclasses()
        return {
            sub.channel_type
            for sub in cls.__subclasses__()
            if getattr(sub, "supports_phone", False)
        }

    @classmethod
    def tenant_phone_channel_types(cls, tenant: Tenant) -> set[str]:
        """Return phone-capable channel types configured on the tenant."""
        phone = cls.phone_channel_types()
        configs = tenant.secrets.channel_configs or {}
        return {typ for typ in configs if typ in phone}

    @classmethod
    def resolve_channel_type(cls, *, typ: str, tenant: Tenant) -> str:
        """
        Resolve the channel type for the given type and tenant.

        If the requested type is configured, return it. Otherwise, if the
        requested type is a phone type (per subclasses with supports_phone),
        fall back to the first available phone-type channel the tenant has
        configured.
        """
        if typ in tenant.secrets.channel_configs:
            return typ
        phone_types = cls.phone_channel_types()
        if typ in phone_types:
            for alt in tenant.secrets.channel_configs:
                if alt in phone_types:
                    return alt
        return typ
