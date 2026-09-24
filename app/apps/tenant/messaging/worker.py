"""
Messaging queue worker.

Consumes messages from the Redis outbox queue and delivers them
via the configured channel providers (Kavenegar, SMTP, Bale, etc.).

Usage:
    python -m apps.tenant.messaging.worker

Environment:
    REDIS_URI  - Redis connection string (default: redis://localhost:6379/)
    LOG_LEVEL  - Logging level (default: INFO)
"""

import asyncio
import json
import logging
import os
import signal

from .services import QUEUE_KEY

logger = logging.getLogger(__name__)


async def process_message(raw: bytes) -> None:
    """Deserialize a queued message and send it via the appropriate channel."""
    from ..models import Tenant
    from .channels.base import AbstractChannel
    from .services import _remote_send_kwargs, arender_template

    payload = json.loads(raw)
    tenant_id = payload["tenant_id"]
    channel_type = payload["channel"]
    to = payload["to"]
    template_type = payload["template_type"]
    context = payload["context"]

    tenant = await Tenant.get_by_uid(tenant_id)
    if not tenant:
        logger.error("Tenant %s not found, dropping message", tenant_id)
        return

    channel_obj = AbstractChannel.create_channel(typ=channel_type, tenant=tenant)

    template = tenant.config.templates.get(template_type)
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
    logger.info("Delivered message for tenant=%s channel=%s", tenant_id, channel_type)


async def run_worker() -> None:
    """Run the main worker loop: BLPOP from the Redis queue and process each message."""
    from server.db import redis

    logger.info("Messaging worker started, listening on %s", QUEUE_KEY)
    shutdown = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("Shutdown signal received")
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    while not shutdown.is_set():
        try:
            result = await redis.blpop(QUEUE_KEY, timeout=5)
            if result is None:
                continue
            _key, raw = result
            try:
                await process_message(raw)
            except Exception:
                # The queue payload can contain OTPs, magic links, and PII.
                logger.exception("Failed to process queued message")
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Worker loop error, retrying in 2s")
            await asyncio.sleep(2)

    logger.info("Messaging worker stopped")


if __name__ == "__main__":
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=log_level, format="[%(levelname)s %(name)s] %(message)s")
    asyncio.run(run_worker())
