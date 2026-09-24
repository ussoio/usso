"""Messaging services."""

import json
import logging
import os

from ..models import Tenant
from .channels.base import AbstractChannel
from .enums import TemplateSourceType, TemplateType
from .templates import MessageTemplate

logger = logging.getLogger(__name__)

QUEUE_KEY = "usso:messaging:outbox"


def _remote_send_kwargs(
    template: MessageTemplate | None, context: dict[str, str]
) -> dict:
    """Build Kavenegar verify_lookup kwargs when using a REMOTE template."""
    if not (
        template
        and template.remote_template_id
        and template.source_type == TemplateSourceType.REMOTE
    ):
        return {}
    kwargs: dict = {"template": template.remote_template_id}
    if "otp" in context:
        kwargs["token"] = context["otp"]
    for key in ("token", "token2", "token3", "token10", "token20"):
        if key in context:
            kwargs[key] = context[key]
    return kwargs


def render_template(
    *, tenant: Tenant, template_type: str, context: dict[str, str]
) -> str:
    """Render a template."""
    template: MessageTemplate | None = tenant.config.templates.get(template_type)

    if not template:
        raise ValueError("Template type not found")

    return template.render(context)


async def arender_template(
    *, tenant: Tenant, template_type: str, context: dict[str, str]
) -> str:
    """Render a template."""
    template: MessageTemplate | None = tenant.config.templates.get(template_type)

    if not template:
        raise ValueError("Template type not found")

    return await template.arender(context)


def _is_queue_enabled() -> bool:
    return os.getenv("MESSAGING_QUEUE_ENABLED", "false").lower() == "true"


async def enqueue_message(
    *,
    tenant_id: str,
    channel: str,
    to: str,
    template_type: str | TemplateType,
    context: dict,
) -> None:
    """Push a message payload onto the Redis outbox queue."""
    from server.db import redis

    payload = json.dumps({
        "tenant_id": tenant_id,
        "channel": channel,
        "to": to,
        "template_type": str(template_type),
        "context": context,
    })
    await redis.rpush(QUEUE_KEY, payload)
    logger.info("Enqueued message for tenant=%s channel=%s", tenant_id, channel)


def send(
    *,
    tenant: Tenant,
    channel: str,
    to: str,
    template_type: str | TemplateType,
    context: dict[str, str],
) -> None:
    """
    Send a message to the user.

    - Check if the channel and template are valid
    - Create channel object for the tenant
    - Create message object based on the template and secret
    - Send message to the user
    """
    channel: AbstractChannel = AbstractChannel.create_channel(
        typ=channel,
        tenant=tenant,
    )

    template: MessageTemplate | None = tenant.config.templates.get(template_type)
    subject = template.subject if template else None

    message = render_template(
        tenant=tenant, template_type=template_type, context=context
    )

    send_kwargs = _remote_send_kwargs(template, context)

    channel.send(
        to=to,
        subject=subject,
        message=message,
        **send_kwargs,
    )


async def asend(
    *,
    tenant: Tenant,
    channel: str,
    to: str,
    template_type: str | TemplateType,
    context: dict[str, str],
) -> None:
    """
    Send a message to the user.

    When MESSAGING_QUEUE_ENABLED=true, the message is pushed to a Redis queue
    for async delivery. Otherwise it sends inline (backward-compatible).
    """
    if _is_queue_enabled():
        serializable_context = _make_serializable(context)
        await enqueue_message(
            tenant_id=tenant.uid,
            channel=channel,
            to=to,
            template_type=template_type,
            context=serializable_context,
        )
        return

    channel_obj: AbstractChannel = AbstractChannel.create_channel(
        typ=channel,
        tenant=tenant,
    )

    template: MessageTemplate | None = tenant.config.templates.get(template_type)
    subject = template.subject if template else None

    message = await arender_template(
        tenant=tenant, template_type=template_type, context=context
    )

    await channel_obj.asend(
        to=to,
        subject=subject,
        message=message,
        **_remote_send_kwargs(template, context),
    )


def _make_serializable(context: dict) -> dict:
    """Convert context values to JSON-serializable types."""
    result = {}
    for k, v in context.items():
        if hasattr(v, "model_dump"):
            result[k] = v.model_dump(mode="json")
        elif hasattr(v, "__dict__"):
            result[k] = str(v)
        else:
            result[k] = v
    return result
