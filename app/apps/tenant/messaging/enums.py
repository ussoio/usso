"""Messaging enums."""

from enum import StrEnum


class MessageChannelType(StrEnum):
    """Message channel type."""

    EMAIL = "email"
    SMS = "sms"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    BALE = "bale"

    @classmethod
    def get_identifier_type(cls, channel_type: str) -> object:
        """
        Get the identifier type.

        Args:
            channel_type: The message channel type
        Returns:
            The identifier type.

        """
        from apps.identity.auth.enums import AuthIdentifier

        return {
            cls.EMAIL: AuthIdentifier.EMAIL,
            cls.SMS: AuthIdentifier.PHONE,
            cls.WHATSAPP: AuthIdentifier.PHONE,
            cls.TELEGRAM: AuthIdentifier.PHONE,
            cls.BALE: AuthIdentifier.PHONE,
        }[channel_type]

    @property
    def identifier_type(self) -> object:
        """
        The identifier type.

        Args:
            self: The message channel type
        Returns:
            The identifier type.

        """
        return self.get_identifier_type(self)


class TemplateType(StrEnum):
    """Template type."""

    verification = "verification"
    reset_password = "reset_password"
    magic_link = "magic_link"
    email_otp = "email_otp"
    sms_otp = "sms_otp"


class TemplateSourceType(StrEnum):
    """Template source type."""

    FILE = "file"
    URL = "url"
    INLINE = "inline"
    REMOTE = "remote"
