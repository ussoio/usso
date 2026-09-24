"""Unit tests for messaging enums."""

from apps.identity.auth.enums import AuthIdentifier
from apps.tenant.messaging.enums import MessageChannelType


def test_message_channel_identifier_type_property() -> None:
    """identifier_type property maps channels to auth identifiers."""
    assert MessageChannelType.EMAIL.identifier_type == AuthIdentifier.EMAIL
    assert MessageChannelType.SMS.identifier_type == AuthIdentifier.PHONE
    assert MessageChannelType.BALE.identifier_type == AuthIdentifier.PHONE
