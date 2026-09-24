"""Focused unit coverage for messaging orchestration services."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from apps.tenant.messaging import services
from apps.tenant.messaging.enums import TemplateSourceType, TemplateType

_REAL_ASEND = services.asend


def _tenant(template: object | None = None) -> SimpleNamespace:
    templates = {"otp": template} if template is not None else {}
    return SimpleNamespace(uid="tenant-1", config=SimpleNamespace(templates=templates))


def test_remote_send_kwargs_only_for_remote_templates() -> None:
    assert services._remote_send_kwargs(None, {}) == {}
    local = SimpleNamespace(
        remote_template_id="remote-id", source_type=TemplateSourceType.INLINE
    )
    assert services._remote_send_kwargs(local, {"otp": "123"}) == {}
    remote = SimpleNamespace(
        remote_template_id="remote-id", source_type=TemplateSourceType.REMOTE
    )
    context = {
        "otp": "123",
        "token": "one",
        "token2": "two",
        "token3": "three",
        "token10": "ten",
        "token20": "twenty",
        "ignored": "x",
    }
    assert services._remote_send_kwargs(remote, context) == {
        "template": "remote-id",
        "token": "one",
        "token2": "two",
        "token3": "three",
        "token10": "ten",
        "token20": "twenty",
    }
    assert services._remote_send_kwargs(remote, {"otp": "123"})["token"] == "123"


def test_render_template_success_and_missing() -> None:
    template = SimpleNamespace(render=MagicMock(return_value="rendered"))
    tenant = _tenant(template)
    assert (
        services.render_template(tenant=tenant, template_type="otp", context={"x": "y"})
        == "rendered"
    )
    template.render.assert_called_once_with({"x": "y"})
    with pytest.raises(ValueError, match="Template type not found"):
        services.render_template(tenant=_tenant(), template_type="otp", context={})


@pytest.mark.asyncio
async def test_arender_template_success_and_missing() -> None:
    template = SimpleNamespace(arender=AsyncMock(return_value="rendered"))
    assert (
        await services.arender_template(
            tenant=_tenant(template), template_type="otp", context={"x": "y"}
        )
        == "rendered"
    )
    with pytest.raises(ValueError, match="Template type not found"):
        await services.arender_template(
            tenant=_tenant(), template_type="otp", context={}
        )


def test_queue_enabled_parses_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MESSAGING_QUEUE_ENABLED", raising=False)
    assert services._is_queue_enabled() is False
    monkeypatch.setenv("MESSAGING_QUEUE_ENABLED", "TrUe")
    assert services._is_queue_enabled() is True


@pytest.mark.asyncio
async def test_enqueue_message_serializes_payload_to_redis() -> None:
    redis = SimpleNamespace(rpush=AsyncMock())
    with patch("server.db.redis", redis):
        await services.enqueue_message(
            tenant_id="tenant-1",
            channel="sms",
            to="0912",
            template_type=TemplateType.sms_otp,
            context={"otp": "123"},
        )
    key, raw = redis.rpush.await_args.args
    assert key == services.QUEUE_KEY
    assert json.loads(raw) == {
        "tenant_id": "tenant-1",
        "channel": "sms",
        "to": "0912",
        "template_type": "sms_otp",
        "context": {"otp": "123"},
    }


def test_send_renders_and_calls_channel_with_remote_kwargs() -> None:
    template = SimpleNamespace(
        subject="OTP",
        remote_template_id="provider-template",
        source_type=TemplateSourceType.REMOTE,
    )
    channel = SimpleNamespace(send=MagicMock())
    tenant = _tenant(template)
    with (
        patch.object(services.AbstractChannel, "create_channel", return_value=channel),
        patch.object(services, "render_template", return_value="body") as render,
    ):
        services.send(
            tenant=tenant,
            channel="sms",
            to="0912",
            template_type="otp",
            context={"otp": "123"},
        )
    render.assert_called_once()
    channel.send.assert_called_once_with(
        to="0912",
        subject="OTP",
        message="body",
        template="provider-template",
        token="123",
    )


@pytest.mark.asyncio
async def test_asend_queue_path_serializes_context() -> None:
    class Item(BaseModel):
        value: int

    tenant = _tenant()
    context = {"model": Item(value=1), "object": SimpleNamespace(value=2), "plain": 3}
    with (
        patch.object(services, "_is_queue_enabled", return_value=True),
        patch.object(services, "enqueue_message", new=AsyncMock()) as enqueue,
    ):
        await _REAL_ASEND(
            tenant=tenant,
            channel="sms",
            to="0912",
            template_type=TemplateType.sms_otp,
            context=context,
        )
    serialized = enqueue.await_args.kwargs["context"]
    assert serialized["model"] == {"value": 1}
    assert isinstance(serialized["object"], str)
    assert serialized["plain"] == 3


@pytest.mark.asyncio
async def test_asend_inline_path_renders_and_sends() -> None:
    template = SimpleNamespace(
        subject=None,
        remote_template_id=None,
        source_type=TemplateSourceType.INLINE,
    )
    channel = SimpleNamespace(asend=AsyncMock())
    tenant = _tenant(template)
    with (
        patch.object(services, "_is_queue_enabled", return_value=False),
        patch.object(services.AbstractChannel, "create_channel", return_value=channel),
        patch.object(services, "arender_template", new=AsyncMock(return_value="body")),
    ):
        await _REAL_ASEND(
            tenant=tenant,
            channel="email",
            to="to@test",
            template_type="otp",
            context={"name": "A"},
        )
    channel.asend.assert_awaited_once_with(to="to@test", subject=None, message="body")
