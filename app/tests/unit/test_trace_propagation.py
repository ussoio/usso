"""
usso: real-app trace ingress/echo and the trace field in the text log format.

Shared adapter behaviour lives in ``../test_tracing.py``.
"""

import asyncio
import logging
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.identity.referral import services as referral
from server.config import Settings
from server.server import app as fastapi_app
from utils.tracing import trace_scope

UUID7 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
INBOUND = "0192f3a4-5b6c-7d8e-9f01-23456789eeee"
SHOP_HOOK = "https://getmirza.ir/api/shop/v1/rewards/webhooks/usso-refer"
WEBHOOK_SECRET = "hook-secret-value"


def test_real_app_mints_echoes_and_replaces() -> None:
    client = TestClient(fastapi_app)
    assert UUID7.match(client.get("/health").headers["X-Trace-ID"])
    assert (
        client.get("/health", headers={"X-Trace-ID": INBOUND}).headers["X-Trace-ID"]
        == INBOUND
    )
    assert UUID7.match(
        client.get("/health", headers={"X-Trace-ID": "a" * 300}).headers["X-Trace-ID"]
    )


def test_error_responses_carry_the_trace_id() -> None:
    response = TestClient(fastapi_app).get(
        "/no-such-route", headers={"X-Trace-ID": INBOUND}
    )
    assert response.status_code == 404
    assert response.headers["X-Trace-ID"] == INBOUND


def test_text_log_format_prints_the_trace_id() -> None:
    config = Settings.get_log_config()["formatters"]["standard"]
    formatter = logging.Formatter(
        config["format"], style=config["style"], defaults=config["defaults"]
    )
    make = logging.getLogger("trace-test").makeRecord
    with trace_scope(INBOUND):
        inside = formatter.format(
            make("t", logging.INFO, "f", 1, "hello", (), None, func="fn")
        )
    outside = formatter.format(
        make("t", logging.INFO, "f", 1, "hello", (), None, func="fn")
    )
    assert f"[trace={INBOUND}] hello" in inside
    assert "[trace=-] hello" in outside


async def test_tenant_webhook_task_inherits_trace_and_keeps_secret_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_PROPAGATE_HOSTS", "getmirza.ir")
    existing_tasks = set(referral._webhook_tasks)
    seen: list[httpx.Request] = []

    async def handle(  # ruff:ignore[unused-async]
        self: object, request: httpx.Request
    ) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    hook = SimpleNamespace(
        url=SHOP_HOOK,
        events=["referral.registered"],
        headers={"X-Webhook-Secret": WEBHOOK_SECRET},
    )
    tenant = SimpleNamespace(
        config=SimpleNamespace(integration=SimpleNamespace(webhooks=[hook]))
    )
    with (
        patch.object(referral, "validate_public_url", new=AsyncMock()),
        trace_scope(INBOUND),
    ):
        referral.dispatch_tenant_webhooks(
            tenant=tenant, event="referral.registered", payload={"referral_code": "abc"}
        )
    await asyncio.gather(*(referral._webhook_tasks - existing_tasks))
    assert seen[0].headers["X-Trace-ID"] == INBOUND
    assert seen[0].headers["X-Webhook-Secret"] == WEBHOOK_SECRET
