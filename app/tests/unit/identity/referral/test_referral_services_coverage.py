"""Focused coverage for referral parsing and webhook notifications."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from apps.identity.referral import services


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("   ", None),
        (" ABC123 ", "ABC123"),
        ("https://app.test/join?referral_code= REF-1 ", "REF-1"),
        ("/join?ref=R2", "R2"),
        ("/join?invite=R3", "R3"),
        ("/join?code=R4", "R4"),
        ("/invite/PATH1", "PATH1"),
        ("https://app.test/r/PATH2", "PATH2"),
        ("/referral/PATH3", "PATH3"),
        ("/unmarked/final", "final"),
        ("?unknown=value", None),
    ],
)
def test_extract_referral_code(raw: str | None, expected: str | None) -> None:
    assert services.extract_referral_code(raw) == expected


@pytest.mark.asyncio
async def test_post_webhook_posts_payload_and_headers() -> None:
    response = SimpleNamespace(raise_for_status=MagicMock())
    client = SimpleNamespace(post=AsyncMock(return_value=response))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)

    with (
        patch.object(services, "validate_public_url", new=AsyncMock()) as validate,
        patch.object(services.httpx, "AsyncClient", return_value=context) as factory,
    ):
        await services._post_webhook(
            url="https://hooks.test/referral",
            headers={"X-Token": "secret"},
            payload={"event": "referral.used"},
        )

    validate.assert_awaited_once_with("https://hooks.test/referral")
    factory.assert_called_once_with(
        timeout=10.0, follow_redirects=False, trust_env=False
    )
    client.post.assert_awaited_once_with(
        "https://hooks.test/referral",
        json={"event": "referral.used"},
        headers={"X-Token": "secret"},
    )
    response.raise_for_status.assert_called_once_with()


@pytest.mark.asyncio
async def test_post_webhook_logs_failures_and_defaults_headers() -> None:
    client = SimpleNamespace(post=AsyncMock(side_effect=RuntimeError("offline")))
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)

    with (
        patch.object(services, "validate_public_url", new=AsyncMock()),
        patch.object(services.httpx, "AsyncClient", return_value=context),
        patch.object(services.logger, "exception") as log,
    ):
        await services._post_webhook(
            url="https://hooks.test/fail", headers=None, payload={"value": 1}
        )

    client.post.assert_awaited_once_with(
        "https://hooks.test/fail", json={"value": 1}, headers={}
    )
    # A non-network error is not transient: one attempt, no retry.
    log.assert_called_once_with(
        "Webhook failed for %s (attempt %d/%d)",
        "https://hooks.test/fail",
        1,
        services.WEBHOOK_ATTEMPTS,
    )


def test_dispatch_tenant_webhooks_ignores_missing_integration() -> None:
    post = MagicMock()
    with patch.object(services, "_post_webhook", post):
        services.dispatch_tenant_webhooks(
            tenant=SimpleNamespace(config=None), event="referral.used", payload={}
        )
    post.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_tenant_webhooks_schedules_only_matching_hooks() -> None:
    matching = SimpleNamespace(
        url="https://hooks.test/match",
        headers={"X-Hook": "yes"},
        events=["referral.used"],
    )
    skipped = SimpleNamespace(
        url="https://hooks.test/skip", headers=None, events=["user.created"]
    )
    tenant = SimpleNamespace(
        config=SimpleNamespace(
            integration=SimpleNamespace(webhooks=[skipped, matching])
        )
    )
    post = AsyncMock()

    with patch.object(services, "_post_webhook", new=post):
        services.dispatch_tenant_webhooks(
            tenant=tenant, event="referral.used", payload={"referral_code": "R1"}
        )
        tasks = list(services._webhook_tasks)
        await __import__("asyncio").gather(*tasks)
        await __import__("asyncio").sleep(0)

    post.assert_awaited_once_with(
        url="https://hooks.test/match",
        headers={"X-Hook": "yes"},
        payload={"event": "referral.used", "referral_code": "R1"},
    )
    assert not services._webhook_tasks


def test_dispatch_tenant_webhooks_handles_empty_hook_list() -> None:
    tenant = SimpleNamespace(
        config=SimpleNamespace(integration=SimpleNamespace(webhooks=None))
    )
    with patch.object(services.asyncio, "create_task") as create_task:
        services.dispatch_tenant_webhooks(
            tenant=tenant, event="referral.used", payload={}
        )
    create_task.assert_not_called()


def test_on_referral_registration_dispatches_all_events() -> None:
    tenant = SimpleNamespace(uid="tenant-1")
    referral = SimpleNamespace(code="R1", user_id="referrer-1", usage_count=3)
    invitee = SimpleNamespace(uid="invitee-1")

    with patch.object(services, "dispatch_tenant_webhooks") as dispatch:
        services.on_referral_registration(
            tenant=tenant, referral=referral, invitee=invitee
        )

    assert dispatch.call_args_list == [
        call(
            tenant=tenant,
            event=services.REFERRAL_REGISTERED_EVENT,
            payload={
                "tenant_id": "tenant-1",
                "referrer_user_id": "referrer-1",
                "invitee_user_id": "invitee-1",
                "referral_code": "R1",
            },
        ),
        call(
            tenant=tenant,
            event=services.REFERRAL_USED_EVENT,
            payload={
                "tenant_id": "tenant-1",
                "referral_code": "R1",
                "referrer_user_id": "referrer-1",
                "invitee_user_id": "invitee-1",
                "usage_count": 3,
            },
        ),
        call(
            tenant=tenant,
            event=services.USER_CREATED_EVENT,
            payload={
                "tenant_id": "tenant-1",
                "user_id": "invitee-1",
                "referral_code": "R1",
                "referrer_user_id": "referrer-1",
            },
        ),
    ]


def test_referral_registered_webhook_body_has_contract_fields() -> None:
    tenant = SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(
            integration=SimpleNamespace(
                webhooks=[
                    SimpleNamespace(
                        url="https://hooks.test/a",
                        headers=None,
                        events=["referral_registered"],
                    )
                ]
            )
        ),
    )
    referral = SimpleNamespace(code="R1", user_id="referrer-1", usage_count=1)
    invitee = SimpleNamespace(uid="invitee-1")

    with (
        patch.object(services, "_post_webhook", new=MagicMock()) as post,
        patch.object(services.asyncio, "create_task") as create_task,
    ):
        services.on_referral_registration(
            tenant=tenant, referral=referral, invitee=invitee
        )

    assert create_task.call_count == 1
    assert post.call_args.kwargs["payload"] == {
        "event": "referral_registered",
        "tenant_id": "tenant-1",
        "referrer_user_id": "referrer-1",
        "invitee_user_id": "invitee-1",
        "referral_code": "R1",
    }
