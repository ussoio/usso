"""test_user_api module."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi_mongo_base.audit.models import AuditLog

from apps.identity.user import routes
from apps.identity.user.models import User


@pytest.mark.asyncio
async def test_retrieve_user(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    response = await authenticated_client.get(f"/users/{uid}")
    resp_json: dict = response.json()
    assert response.status_code == 200
    assert "identifiers" in resp_json
    assert len(resp_json["identifiers"]) == len(
        await sample_user.get_identifiers(not_cached=True)
    )
    assert (
        resp_json["identifiers"][0]["type"]
        == (await sample_user.get_identifiers())[0].type
        for i in range(len(resp_json["identifiers"]))
    )
    assert (
        resp_json["identifiers"][0]["identifier"]
        == (await sample_user.get_identifiers())[0].identifier
        for i in range(len(resp_json["identifiers"]))
    )
    assert resp_json["uid"] == uid


@pytest.mark.asyncio
async def test_create_user(authenticated_client: httpx.AsyncClient) -> None:
    response = await authenticated_client.post(
        "/users",
        json={
            "identifier_type": "email",
            "identifier": "test_create_user@gmail.com",
        },
    )
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 201

    audit_rows = await AuditLog.find({
        "resource_type": "User",
        "resource_uid": resp_json["uid"],
        "action": "create",
    }).to_list()
    assert len(audit_rows) == 1
    assert audit_rows[0].actor_sub_type == "user"
    assert audit_rows[0].actor_user_id is not None


@pytest.mark.asyncio
async def test_list_users(authenticated_client: httpx.AsyncClient) -> None:
    response = await authenticated_client.get("/users")
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 200
    assert "items" in resp_json
    assert len(resp_json["items"]) == resp_json["total"]


@pytest.mark.asyncio
async def test_update_user(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid
    response = await authenticated_client.patch(
        f"/users/{uid}",
        json={
            "name": "test_update_user",
        },
    )
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 200
    assert resp_json["name"] == "test_update_user"

    audit_rows = await AuditLog.find({
        "resource_type": "User",
        "resource_uid": uid,
        "action": "update",
    }).to_list()
    assert audit_rows
    assert audit_rows[-1].changes is not None
    assert "name" in audit_rows[-1].changes

    response = await authenticated_client.get(f"/users/{uid}")
    resp_json: dict = response.json()
    assert response.status_code == 200
    assert resp_json["name"] == "test_update_user"


@pytest.mark.asyncio
async def test_update_user_permission(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid

    response = await authenticated_client.get("/sessions", params={"user_id": uid})
    resp_json: dict = response.json()
    assert response.status_code == 200
    logging.info(f"{resp_json}")
    assert "*:*" not in resp_json["items"][0]["scopes"]

    response = await authenticated_client.patch(
        f"/users/{uid}",
        json={"roles": ["admin"]},
    )
    resp_json: dict = response.json()
    logging.info(f"{resp_json}")
    assert response.status_code == 200
    assert resp_json["roles"] == ["admin"]

    response = await authenticated_client.get("/sessions", params={"user_id": uid})
    resp_json: dict = response.json()
    assert response.status_code == 200
    assert "*:*" in resp_json["items"][0]["scopes"]


@pytest.mark.asyncio
async def test_impersonate_user(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid

    caller = SimpleNamespace(
        uid="admin-1",
        user_id="admin-1",
        tenant_id=sample_user.tenant_id,
        scopes=["*:*"],
        workspace_id=None,
    )
    with (
        patch.object(
            routes.UserRouter,
            "get_user",
            new=AsyncMock(return_value=caller),
        ),
        patch.object(
            routes.UserRouter,
            "authorize",
            new=AsyncMock(return_value=True),
        ),
    ):
        response = await authenticated_client.post(
            f"/users/{uid}/impersonate",
            json={"mode": "full"},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["sub"] == uid
    assert "impersonation" in (body.get("amr") or [])
    assert body.get("impersonated_by")
    assert body.get("impersonation_mode") == "full"

    response = await authenticated_client.get("/sessions", params={"user_id": uid})
    assert response.status_code == 200
    items = response.json().get("items") or []
    impersonation_sessions = [
        s for s in items if s.get("session_type") == "impersonation"
    ]
    assert impersonation_sessions
    assert impersonation_sessions[0]["user_id"] == uid
    assert impersonation_sessions[0]["meta_data"]["impersonated_by"]
    assert impersonation_sessions[0]["meta_data"]["impersonation_mode"] == "full"


@pytest.mark.asyncio
async def test_delete_user(
    authenticated_client: httpx.AsyncClient, sample_user: User
) -> None:
    uid = sample_user.uid

    response = await authenticated_client.delete(f"/users/{uid}")
    assert response.status_code == 200

    response = await authenticated_client.get("/users")
    assert uid not in [item["uid"] for item in response.json().get("items")]
