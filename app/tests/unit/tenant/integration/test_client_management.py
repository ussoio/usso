"""Unit tests for OAuth client management helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.tenant.integration import client_management as cm
from apps.tenant.integration.schemas import GrantType, ResponseType


@pytest.mark.asyncio
async def test_validate_client_helpers_when_missing() -> None:
    """Missing clients return False/empty for validation helpers."""
    tenant = MagicMock()
    with patch.object(
        cm, "get_oauth_client", new_callable=AsyncMock, return_value=None
    ):
        assert await cm.validate_client_redirect_uri(tenant, "c1", "https://x") is False
        assert await cm.get_client_scopes(tenant, "c1") == []
        assert await cm.is_client_active(tenant, "c1") is False
        assert await cm.validate_client_scopes(tenant, "c1", ["openid"]) is False


@pytest.mark.asyncio
async def test_validate_client_helpers_when_present() -> None:
    """Active client validates redirect URI and scopes."""
    tenant = MagicMock()
    client = MagicMock()
    client.redirect_uris = ["https://app.test/cb"]
    client.allowed_scopes = [
        SimpleNamespace(value="openid"),
        SimpleNamespace(value="profile"),
    ]
    client.is_active = True

    with patch.object(
        cm, "get_oauth_client", new_callable=AsyncMock, return_value=client
    ):
        assert (
            await cm.validate_client_redirect_uri(tenant, "c1", "https://app.test/cb")
            is True
        )
        assert (
            await cm.validate_client_redirect_uri(tenant, "c1", "https://other")
            is False
        )
        assert await cm.get_client_scopes(tenant, "c1") == ["openid", "profile"]
        assert await cm.is_client_active(tenant, "c1") is True
        # validate_client_scopes compares requested strings against stored scopes
        client.allowed_scopes = ["openid", "profile"]
        assert await cm.validate_client_scopes(tenant, "c1", ["openid"]) is True
        assert await cm.validate_client_scopes(tenant, "c1", ["admin"]) is False


@pytest.mark.asyncio
async def test_update_and_deactivate_and_regenerate() -> None:
    """Update/deactivate/regenerate operate on found clients only."""
    tenant = MagicMock()
    client = MagicMock()
    client.is_active = True
    client.save = AsyncMock()

    with (
        patch.object(cm, "get_oauth_client", new_callable=AsyncMock) as get_client,
        patch.object(
            cm.OAuthClient, "update_item", new_callable=AsyncMock, return_value=client
        ),
        patch.object(
            cm.OAuthClient,
            "generate_client_secret",
            return_value="new-secret",
        ),
    ):
        get_client.return_value = None
        assert await cm.update_oauth_client(tenant, "c1", client_name="x") is None
        assert await cm.deactivate_oauth_client(tenant, "c1") is False
        assert await cm.regenerate_client_secret(tenant, "c1") is None

        get_client.return_value = client
        assert await cm.update_oauth_client(tenant, "c1", client_name="x") is client
        assert await cm.deactivate_oauth_client(tenant, "c1") is True
        assert client.is_active is False
        assert await cm.regenerate_client_secret(tenant, "c1") == "new-secret"
        assert cm.PasswordHasherService().verify_password(
            client.client_secret, "new-secret"
        )


@pytest.mark.asyncio
async def test_create_and_list_oauth_clients() -> None:
    """create_oauth_client saves a new client; list returns query results."""
    tenant = MagicMock()
    tenant.uid = "t1"
    tenant.user_id = "owner-1"

    client = MagicMock()
    client.save = AsyncMock()
    query = MagicMock()
    query.to_list = AsyncMock(return_value=[client])

    with (
        patch.object(cm.OAuthClient, "generate_client_id", return_value="cid"),
        patch.object(
            cm.OAuthClient,
            "generate_client_secret",
            return_value="csecret",
        ),
        patch.object(cm, "OAuthClient", return_value=client) as client_cls,
    ):
        # Keep classmethods used after construction patching
        client_cls.generate_client_id = MagicMock(return_value="cid")
        client_cls.generate_client_secret = MagicMock(return_value="csecret")
        client_cls.get_query = MagicMock(return_value=query)
        client_cls.return_value = client

        created = await cm.create_oauth_client(
            tenant=tenant,
            client_name="App",
            redirect_uris=["https://app.test/cb"],
        )
        listed = await cm.list_oauth_clients(tenant)

    assert created is client
    client.save.assert_awaited_once()
    assert listed == [client]


@pytest.mark.asyncio
async def test_get_oauth_client_delegates() -> None:
    """get_oauth_client looks up by client_id and tenant."""
    tenant = MagicMock()
    tenant.uid = "t1"
    with patch.object(
        cm.OAuthClient,
        "get_by_client_id",
        new_callable=AsyncMock,
        return_value=MagicMock(),
    ) as get_by:
        result = await cm.get_oauth_client(tenant, "cid")
    assert result is get_by.return_value
    get_by.assert_awaited_once_with("cid", "t1")


@pytest.mark.asyncio
async def test_create_default_oauth_client_delegates() -> None:
    """Default client creation delegates to create_oauth_client."""
    tenant = MagicMock()
    tenant.name = "Acme"
    with patch.object(cm, "create_oauth_client", new_callable=AsyncMock) as create:
        create.return_value = MagicMock()
        result = await cm.create_default_oauth_client(tenant)
        assert result is create.return_value
        kwargs = create.await_args.kwargs
        assert kwargs["tenant"] is tenant
        assert "Default Client" in kwargs["client_name"]
        assert GrantType.AUTHORIZATION_CODE in kwargs["grant_types"]
        assert ResponseType.CODE in kwargs["response_types"]
