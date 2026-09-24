"""Focused unit coverage for messaging channel base, SMTP, and generic helpers."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

import apps.tenant.messaging.channels  # ruff: ignore[unused-import]
from apps.tenant.messaging.channels.base import AbstractChannel
from apps.tenant.messaging.channels.email import (
    SMTPConfig,
    SMTPEmailChannel,
    send_email,
)
from server.exceptions import BadRequestError


class DummyConfig(BaseModel):
    value: str


class DummyChannel(AbstractChannel):
    channel_type = "dummy"
    ConfigType = DummyConfig

    def send(
        self, *, to: str, message: str, subject: str | None = None, **kwargs: object
    ) -> None:
        self.last_send = (to, message, subject, kwargs)


def _tenant(configs: dict) -> SimpleNamespace:
    return SimpleNamespace(secrets=SimpleNamespace(channel_configs=configs))


def test_channel_init_accepts_model_and_dict_configs() -> None:
    model = DummyConfig(value="model")
    channel = DummyChannel(
        tenant=_tenant({"dummy": SimpleNamespace(provider_config=model)})
    )
    assert channel.config is model

    channel = DummyChannel(
        tenant=_tenant({"dummy": SimpleNamespace(provider_config={"value": "dict"})})
    )
    assert channel.config.value == "dict"


def test_channel_init_rejects_missing_and_invalid_configs() -> None:
    with pytest.raises(BadRequestError) as exc:
        DummyChannel(tenant=_tenant({}))
    assert exc.value.error_code == "channel_not_found"

    with pytest.raises(TypeError, match="Invalid SMS config"):
        DummyChannel(
            tenant=_tenant({"dummy": SimpleNamespace(provider_config=object())})
        )


@pytest.mark.asyncio
async def test_channel_factory_validation_async_send_and_resolution() -> None:
    tenant = _tenant({"dummy": SimpleNamespace(provider_config={"value": "ok"})})
    channel = AbstractChannel.create_channel(typ="dummy", tenant=tenant)
    assert isinstance(channel, DummyChannel)
    assert AbstractChannel.validate_type(typ="dummy") is True
    assert AbstractChannel.validate_type(typ="missing") is False
    await channel.asend(to="target", message="message", subject="subject", extra=1)
    assert channel.last_send == ("target", "message", "subject", {"extra": 1})
    with pytest.raises(ValueError, match="Channel type missing not found"):
        AbstractChannel.create_channel(typ="missing", tenant=tenant)

    phone_tenant = _tenant({"email": object(), "bale": object()})
    assert (
        AbstractChannel.resolve_channel_type(typ="email", tenant=phone_tenant)
        == "email"
    )
    assert (
        AbstractChannel.resolve_channel_type(typ="sms", tenant=phone_tenant) == "bale"
    )
    assert (
        AbstractChannel.resolve_channel_type(typ="unknown", tenant=phone_tenant)
        == "unknown"
    )
    assert "dummy" not in AbstractChannel.phone_channel_types()
    assert AbstractChannel.tenant_phone_channel_types(phone_tenant) == {"bale"}


def _smtp_config(**overrides: object) -> SMTPConfig:
    values = {
        "host": "smtp.test",
        "port": 465,
        "username": "user",
        "password": "pass",
        "sender": "sender@test",
    }
    values.update(overrides)
    return SMTPConfig(**values)


def test_send_email_uses_ssl_login_and_message_headers() -> None:
    server = MagicMock()
    config = _smtp_config()
    with patch(
        "apps.tenant.messaging.channels.email.smtplib.SMTP_SSL", return_value=server
    ) as smtp:
        send_email(
            smtp_config=config,
            to_email="to@test",
            text="<b>Hello</b>",
            subject="Subject",
        )
    smtp.assert_called_once_with("smtp.test", 465, timeout=30)
    server.login.assert_called_once_with("user", "pass")
    args = server.sendmail.call_args.args
    assert args[:2] == ("sender@test", ["to@test"])
    assert "Subject: Subject" in args[2]
    server.quit.assert_called_once_with()


def test_send_email_plain_smtp_starts_tls_and_can_skip_login() -> None:
    server = MagicMock()
    config = _smtp_config(
        port=587, use_ssl=False, use_tls=True, username="", password=""
    )
    with patch(
        "apps.tenant.messaging.channels.email.smtplib.SMTP", return_value=server
    ):
        send_email(smtp_config=config, to_email="to@test", text="hello")
    server.starttls.assert_called_once_with()
    server.login.assert_not_called()
    server.sendmail.assert_called_once()


def test_smtp_channel_delegates_to_send_email() -> None:
    channel = object.__new__(SMTPEmailChannel)
    channel.config = _smtp_config()
    with patch("apps.tenant.messaging.channels.email.send_email") as send:
        channel.send(to="to@test", message="body", subject="subject")
    send.assert_called_once_with(
        smtp_config=channel.config,
        to_email="to@test",
        text="body",
        subject="subject",
    )
