"""test_tenant module."""

import logging

import httpx
import pytest


@pytest.mark.asyncio
async def test_create_tenant(authenticated_client: httpx.AsyncClient) -> None:
    res = await authenticated_client.post(
        "/tenants",
        json={"name": "test", "domains": ["new-tenant.usso.io"]},
    )
    if res.status_code != 201:
        logging.error(res.json())
    assert res.status_code == 201
