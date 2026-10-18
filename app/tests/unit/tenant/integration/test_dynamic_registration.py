"""RFC 7591 open registration of public PKCE clients for MCP agents."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from apps.tenant.integration import routes, services
from apps.tenant.integration.schemas import (
    GrantType,
    PublicClientRegistrationSchema,
    ResponseType,
    Scope,
)


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(uid="tenant-1", user_id="owner-1")


def test_schema_ignores_unknown_fields_and_defaults_to_public_code_flow() -> None:
    body = PublicClientRegistrationSchema(
        client_name="Cursor",
        redirect_uris=["http://127.0.0.1:33418/callback"],
        token_endpoint_auth_method="none",
        application_type="native",
        unknown_future_field=1,
    )
    assert body.grant_types == [GrantType.AUTHORIZATION_CODE]
    assert body.response_types == [ResponseType.CODE]


@pytest.mark.parametrize(
    "uris",
    [
        ["http://evil.example/callback"],
        ["javascript:alert(1)"],
        ["https://user:pw@app.test/cb"],
        ["https://app.test/cb#frag"],
        [],
    ],
)
def test_schema_rejects_unsafe_redirect_uris(uris: list[str]) -> None:
    with pytest.raises(ValidationError):
        PublicClientRegistrationSchema(client_name="x", redirect_uris=uris)


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "http://localhost:6274/oauth/callback",
        "cursor://anysphere.cursor-retrieval/oauth/callback",
    ],
)
def test_schema_accepts_any_agent_redirect(uri: str) -> None:
    assert PublicClientRegistrationSchema(
        client_name="Agent", redirect_uris=[uri]
    ).redirect_uris == [uri]


def test_schema_rejects_non_public_auth_method() -> None:
    with pytest.raises(ValidationError):
        PublicClientRegistrationSchema(
            client_name="x",
            redirect_uris=["https://app.test/cb"],
            token_endpoint_auth_method="client_secret_basic",
        )


@pytest.mark.asyncio
async def test_register_public_client_forces_safe_settings() -> None:
    saved: list[object] = []

    class FakeClient(SimpleNamespace):
        async def save(self) -> None:
            saved.append(self)

    body = PublicClientRegistrationSchema(
        client_name="Agent",
        redirect_uris=["https://app.test/cb"],
        grant_types=[GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN],
        scope="openid read write admin",
    )
    with patch.object(services, "OAuthClient", FakeClient):
        services.OAuthClient.generate_client_id = staticmethod(lambda: "uc_x")
        result = await services.register_public_client(body, _tenant())

    (client,) = saved
    assert client.client_secret is None
    assert client.require_pkce is True
    assert client.require_consent is True
    assert client.token_endpoint_auth_method == "none"
    assert client.user_id == services.DYNAMIC_REGISTRATION_USER_ID
    assert client.user_id != _tenant().user_id
    assert Scope.OPENID in client.allowed_scopes
    assert "admin" not in [str(s) for s in client.allowed_scopes]
    assert result["client_id"] == "uc_x"
    assert result["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in result
    assert result["scope"] == "openid read write"


def test_dynamic_client_tokens_are_bound_to_configured_resources() -> None:
    dynamic = SimpleNamespace(
        client_id="uc_x", user_id=services.DYNAMIC_REGISTRATION_USER_ID
    )
    first_party = SimpleNamespace(client_id="mirza-flow", user_id="owner-1")
    with patch.object(
        services.Settings,
        "dynamic_client_audiences",
        ("https://resource.example.test/mcp",),
    ):
        assert services.access_token_audience(dynamic) == [
            "uc_x",
            "https://resource.example.test/mcp",
        ]
        assert services.access_token_audience(first_party) == "mirza-flow"


def test_without_configured_resources_audience_is_unchanged() -> None:
    dynamic = SimpleNamespace(
        client_id="uc_x", user_id=services.DYNAMIC_REGISTRATION_USER_ID
    )
    with patch.object(services.Settings, "dynamic_client_audiences", ()):
        assert services.access_token_audience(dynamic) == "uc_x"


@pytest.mark.asyncio
async def test_register_endpoint_needs_no_login() -> None:
    body = PublicClientRegistrationSchema(
        client_name="Agent", redirect_uris=["https://app.test/cb"]
    )
    expected = {"client_id": "uc_x"}
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=_tenant())),
        patch.object(
            routes, "register_public_client", new=AsyncMock(return_value=expected)
        ) as register,
    ):
        response = await routes.register_public_client_endpoint(MagicMock(), body)
    assert response.status_code == 201
    register.assert_awaited_once()
