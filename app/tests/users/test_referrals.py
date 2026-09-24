"""test_referrals module."""

import logging
from unittest.mock import patch

import httpx
import pytest

from apps.identity.referral.models import ReferralCode
from apps.tenant.models import Tenant
from server.server import app as fastapi_app


@pytest.mark.asyncio
async def test_create_referral_code(
    authenticated_client: httpx.AsyncClient,
) -> None:
    me_response = await authenticated_client.get("/auth/me")
    me_response.raise_for_status()
    caller_uid = me_response.json()["sub"]

    resp = await authenticated_client.post("/referrals", json={})
    logging.info(resp.json())
    assert resp.status_code == 201  # self-service create for your own user_id
    assert resp.json()["user_id"] == caller_uid


@pytest.mark.asyncio
async def test_create_user_with_referral(
    authenticated_client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    referral = ReferralCode(
        tenant_id=initial_tenant.uid,
        user_id="test-referrer-valid",
        code="test-create-user-referral-valid",
        usage_count=2,
        max_usage=5,
    )
    await referral.save()

    with patch("apps.identity.referral.services.dispatch_tenant_webhooks") as dispatch:
        response = await authenticated_client.post(
            "/users",
            json={
                "identifier_type": "email",
                "identifier": "test_create_user_with_referral_1@gmail.com",
                "referral_code": referral.code,
            },
        )

    assert response.status_code == 201
    reloaded = await ReferralCode.get_by_code(
        code=referral.code,
        tenant_id=initial_tenant.uid,
    )
    assert reloaded is not None
    assert reloaded.usage_count == 2
    dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_create_user_without_referral(
    authenticated_client: httpx.AsyncClient,
) -> None:
    with (
        patch("apps.identity.referral.services.dispatch_tenant_webhooks") as dispatch,
    ):
        response = await authenticated_client.post(
            "/users",
            json={
                "identifier_type": "email",
                "identifier": "test_create_user_without_referral_2@gmail.com",
            },
        )

    assert response.status_code == 201
    dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_create_user_with_exhausted_referral(
    authenticated_client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    referral = ReferralCode(
        tenant_id=initial_tenant.uid,
        user_id="test-referrer-exhausted",
        code="test-create-user-referral-exhausted",
        usage_count=3,
        max_usage=3,
    )
    await referral.save()

    with patch("apps.identity.referral.services.dispatch_tenant_webhooks") as dispatch:
        response = await authenticated_client.post(
            "/users",
            json={
                "identifier_type": "email",
                "identifier": "test_create_user_with_exhausted_referral_3@gmail.com",
                "referral_code": referral.code,
            },
        )

    assert response.status_code == 201
    reloaded = await ReferralCode.get_by_code(
        code=referral.code,
        tenant_id=initial_tenant.uid,
    )
    assert reloaded is not None
    assert reloaded.usage_count == 3
    dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_existing_user_does_not_consume_referral(
    authenticated_client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    identifier = "test_existing_user_does_not_consume_referral_4@gmail.com"
    first_response = await authenticated_client.post(
        "/users",
        json={"identifier_type": "email", "identifier": identifier},
    )
    assert first_response.status_code == 201

    referral = ReferralCode(
        tenant_id=initial_tenant.uid,
        user_id="test-referrer-existing-user",
        code="test-existing-user-referral-valid",
        usage_count=0,
        max_usage=5,
    )
    await referral.save()

    with patch("apps.identity.referral.services.dispatch_tenant_webhooks") as dispatch:
        response = await authenticated_client.post(
            "/users",
            json={
                "identifier_type": "email",
                "identifier": identifier,
                "referral_code": referral.code,
            },
        )

    assert response.status_code == 400
    reloaded = await ReferralCode.get_by_code(
        code=referral.code,
        tenant_id=initial_tenant.uid,
    )
    assert reloaded is not None
    assert reloaded.usage_count == 0
    dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_list_referral_codes_by_user_id(
    authenticated_client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    target_referral = ReferralCode(
        tenant_id=initial_tenant.uid,
        user_id="test-list-referrals-target",
        code="test-list-referrals-target-code",
    )
    other_referral = ReferralCode(
        tenant_id=initial_tenant.uid,
        user_id="test-list-referrals-other",
        code="test-list-referrals-other-code",
    )
    await target_referral.save()
    await other_referral.save()

    response = await authenticated_client.get(
        "/referrals",
        params={"user_id": target_referral.user_id},
    )

    assert response.status_code == 200
    assert {item["code"] for item in response.json()["items"]} == {target_referral.code}


@pytest.mark.asyncio
async def test_service_caller_creates_referral_for_another_user(
    authenticated_client: httpx.AsyncClient,
    initial_tenant: Tenant,
) -> None:
    target_user_id = "telegram-42"
    me_response = await authenticated_client.get("/auth/me")
    me_response.raise_for_status()
    assert me_response.json()["sub"] != target_user_id

    api_key_response = await authenticated_client.post(
        "/apikeys",
        json={"scopes": ["*:*"]},
    )
    api_key_response.raise_for_status()
    generated_api_key = api_key_response.json()["api_key"]
    api_key_uid = api_key_response.json()["uid"]
    code = "test-service-create-referral-code"

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fastapi_app),
            base_url=authenticated_client.base_url,
            headers={"x-api-key": generated_api_key},
        ) as service_client:
            response = await service_client.post(
                "/referrals",
                json={"user_id": target_user_id, "code": code},
            )

        assert response.status_code == 201
        assert response.json()["user_id"] == target_user_id
        persisted = await ReferralCode.get_by_code(
            code=code,
            tenant_id=initial_tenant.uid,
        )
        assert persisted is not None
        assert persisted.user_id == target_user_id
    finally:
        await authenticated_client.delete(f"/apikeys/{api_key_uid}")

    # Note: a *scope-restricted* API key was deliberately not tested for
    # rejection here. `authorize_create_on_behalf` (shared
    # fastapi_mongo_base helper) treats any authenticated service/API-key
    # caller as trusted for on-behalf creation regardless of which specific
    # scopes that key holds -- the same "service caller, trust broadly"
    # model already established elsewhere in this ecosystem (ai-toolkit,
    # media). The real authorization boundary this helper enforces is the
    # JWT branch: a plain end-user JWT can only create for their own
    # user_id (covered by test_create_referral_code above) and must go
    # through router.authorize() for anyone else's -- not exercised end-to-
    # end here since it would require a second, genuinely low-privilege
    # registered user (this suite's authenticated_client is always the
    # wildcard-scoped tenant admin), which isn't worth the fixture cost for
    # this repo's existing test infrastructure.
