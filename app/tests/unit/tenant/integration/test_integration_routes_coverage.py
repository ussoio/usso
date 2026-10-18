"""Focused direct-call coverage for OAuth/OIDC route handlers."""

import base64
from collections.abc import Iterator
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.responses import RedirectResponse
from fastapi_mongo_base.utils import timezone

from apps.tenant.integration import routes
from apps.tenant.integration.schemas import (
    ClientRegistrationRequestSchema,
    ClientUpdateSchema,
    GrantType,
    OuathDeviceAuthorizationDecisionSchema,
    ResponseType,
)
from server.exceptions import (
    BadRequestError,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from utils.hasher import PasswordHasherService

OAUTH_CLIENT_SECRET_HASH = PasswordHasherService().hash_password("secret-value")


@pytest.fixture(autouse=True)
def _mock_recent_authentication() -> object:
    """Keep direct handler tests focused on route behavior after step-up."""
    with patch.object(routes, "require_secure_token") as require:
        yield require


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        primary_url="https://tenant.test",
        get_frontend_url=MagicMock(
            side_effect=lambda page: f"https://frontend.test/{page}"
        ),
    )


def _request(
    *, headers: dict[str, str] | None = None, form: dict[str, str] | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        url="https://tenant.test/oauth/authorize?client_id=client-1",
        headers=headers or {},
        form=AsyncMock(return_value=form or {}),
    )


def _client(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "client_id": "client-1",
        "client_secret": OAUTH_CLIENT_SECRET_HASH,
        "client_name": "Coverage Client",
        "client_type": "confidential",
        "redirect_uris": ["https://client.test/callback"],
        "allowed_scopes": ["openid", "profile"],
        "grant_types": [GrantType.AUTHORIZATION_CODE],
        "response_types": [ResponseType.CODE],
        "logo_uri": None,
        "client_uri": None,
        "policy_uri": None,
        "tos_uri": None,
        "require_pkce": False,
        "token_endpoint_auth_method": "client_secret_post",
        "is_active": True,
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.tz),
        "registration_access_token": "registration-token",
        "user_id": "user-1",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _token_kwargs(grant_type: object, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "request": _request(),
        "grant_type": grant_type,
        "client_id": "client-1",
        "client_secret": "secret-value",
        "code": None,
        "redirect_uri": None,
        "code_verifier": None,
        "refresh_token": None,
        "scope": None,
        "device_code": None,
    }
    values.update(overrides)
    return values


@pytest.fixture(autouse=True)
def _no_stored_consent() -> Iterator[None]:
    """Default: no persisted consent; grants are not written to the database."""
    with (
        patch.object(routes.UserConsent, "covers", new=AsyncMock(return_value=False)),
        patch.object(routes.UserConsent, "grant", new=AsyncMock()),
    ):
        yield


@pytest.mark.asyncio
async def test_token_rejects_malformed_and_conflicting_basic_auth() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError) as malformed,
    ):
        await routes.token(
            **_token_kwargs(
                GrantType.AUTHORIZATION_CODE,
                request=_request(headers={"authorization": "Basic !!!"}),
            )
        )
    assert malformed.value.error_code == "invalid_client"

    encoded = base64.b64encode(b"basic-client:secret").decode()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError, match="Conflicting client IDs"),
    ):
        await routes.token(
            **_token_kwargs(
                GrantType.AUTHORIZATION_CODE,
                request=_request(headers={"authorization": f"Basic {encoded}"}),
                client_id="form-client",
            )
        )


@pytest.mark.asyncio
async def test_handle_authorized_user_returns_code_redirect() -> None:
    tenant = _tenant()
    client = _client()
    user = SimpleNamespace(uid="user-1")
    create_code = AsyncMock(return_value=SimpleNamespace(code="auth-code"))
    with patch.object(routes, "create_authorization_code", new=create_code):
        response = await routes._handle_authorized_user(
            client,
            user,
            tenant,
            ResponseType.CODE,
            "https://client.test/callback",
            ["openid"],
            "nonce-1",
            "state-1",
        )
    assert isinstance(response, RedirectResponse)
    assert response.headers["location"] == (
        "https://client.test/callback?code=auth-code&state=state-1"
    )
    create_code.assert_awaited_once_with(
        client=client,
        user=user,
        tenant=tenant,
        redirect_uri="https://client.test/callback",
        scope=["openid"],
        nonce="nonce-1",
        code_challenge=None,
        code_challenge_method=None,
    )


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_authorize_redirects_unauthenticated_user_to_login() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(return_value=(_client(), ["openid"])),
        ),
        patch.object(
            routes.dependencies,
            "get_current_user_optional",
            new=AsyncMock(return_value=None),
        ),
    ):
        response = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "client-1",
            "https://client.test/callback",
            "openid",
            "state-1",
            None,
            "S256",
            None,
            None,
            None,
            provider=None,
        )
    assert response.headers["location"].startswith(
        "https://frontend.test/login?redirect_to="
    )


@pytest.mark.asyncio
async def test_authorize_rejects_replayed_consented_session() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    session = SimpleNamespace(
        is_consented=True,
        user_id="user-1",
        client_id="client-1",
        redirect_uri="https://client.test/callback",
        scope=["openid"],
        nonce="nonce-1",
        code_challenge=None,
        code_challenge_method="S256",
    )
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(return_value=(_client(), ["openid"])),
        ),
        patch.object(
            routes.dependencies,
            "get_current_user_optional",
            new=AsyncMock(return_value=user),
        ),
        patch.object(
            routes.OAuthSession,
            "get_by_state",
            new=AsyncMock(return_value=session),
        ),
        patch.object(
            routes, "_handle_authorized_user", new_callable=AsyncMock
        ) as handle,
    ):
        result = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "client-1",
            "https://client.test/callback",
            "openid",
            "state-1",
            None,
            "S256",
            "nonce-1",
            None,
            None,
        )
    assert "error=invalid_request" in result.headers["location"]
    handle.assert_not_awaited()


@pytest.mark.asyncio
async def test_authorize_creates_session_and_redirects_to_consent() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    session = SimpleNamespace(save=AsyncMock())
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(return_value=(_client(), ["openid", "profile"])),
        ),
        patch.object(
            routes.dependencies,
            "get_current_user_optional",
            new=AsyncMock(return_value=user),
        ),
        patch.object(
            routes.OAuthSession, "create_session", return_value=session
        ) as create_session,
    ):
        response = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "client-1",
            "https://client.test/callback",
            "openid profile",
            None,
            None,
            "S256",
            None,
            None,
            None,
        )
    assert response.headers["location"].startswith(
        "https://frontend.test/consent?client_id=client-1"
    )
    create_session.assert_called_once()
    session.save.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_authorize_skips_consent_when_require_consent_false() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    client = _client()
    client.require_consent = False
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(return_value=(client, ["openid", "profile"])),
        ),
        patch.object(
            routes.dependencies,
            "get_current_user_optional",
            new=AsyncMock(return_value=user),
        ),
        patch.object(
            routes,
            "_handle_authorized_user",
            new=AsyncMock(
                return_value=RedirectResponse("ir.getmirza.flow:/oauth?code=xyz")
            ),
        ) as handle,
    ):
        response = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "mirza-flow",
            "ir.getmirza.flow:/oauth",
            "openid profile",
            "state_1234567890123456",
            None,
            "S256",
            None,
            None,
            None,
        )
    assert response.headers["location"] == "ir.getmirza.flow:/oauth?code=xyz"
    handle.assert_awaited_once()


@pytest.mark.asyncio
async def test_authorize_turns_http_errors_into_oauth_redirect() -> None:
    tenant = _tenant()
    error = BadRequestError(
        error_code="invalid_request",
        detail="bad redirect",
        message={"en": "bad", "fa": "bad"},
    )
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(side_effect=error),
        ),
    ):
        response = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "client-1",
            "https://client.test/callback",
            None,
            "state-1",
            None,
            "S256",
            None,
            None,
            None,
        )
    location = response.headers["location"]
    assert location.startswith("https://frontend.test/oauth_authorize?")
    assert "error=invalid_request" in location
    assert "state=state-1" in location


def _oauth_session(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "user_id": "user-1",
        "is_consented": False,
        "is_consumed": False,
        "created_at": datetime.now(timezone.tz),
        "is_expired": MagicMock(return_value=False),
        "client_id": "client-1",
        "redirect_uri": "https://client.test/callback",
        "scope": ["openid", "", " profile "],
        "nonce": "nonce-1",
        "grant_consent": MagicMock(),
        "save": AsyncMock(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.asyncio
async def test_consent_authorize_rejects_invalid_session() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(
            routes.OAuthSession, "get_by_state", new=AsyncMock(return_value=None)
        ),
    ):
        response = await routes.consent_authorize(_request(), "state-1", True)
    assert "oauth_failed" in response.headers["location"]
    assert "Invalid+session" in response.headers["location"]


@pytest.mark.asyncio
async def test_consent_authorize_handles_missing_client_and_denial() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    session = _oauth_session()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(
            routes.OAuthSession,
            "get_by_state",
            new=AsyncMock(return_value=session),
        ),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=None)),
        patch.object(routes.status, "HTTP_303", 303, create=True),
    ):
        missing = await routes.consent_authorize(_request(), "state-1", True)
    assert missing.status_code == 303
    assert "oauth_failed" in missing.headers["location"]

    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(
            routes.OAuthSession,
            "get_by_state",
            new=AsyncMock(return_value=session),
        ),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=_client())),
        patch.object(
            routes,
            "consume_oauth_consent",
            new=AsyncMock(return_value=True),
        ) as consume,
    ):
        denied = await routes.consent_authorize(_request(), "state-1", False)
    assert denied.status_code == 302
    assert "error=access_denied" in denied.headers["location"]
    assert "state=state-1" in denied.headers["location"]
    consume.assert_awaited_once_with(session, granted_scope=[], consented=False)


@pytest.mark.asyncio
async def test_consent_authorize_grants_scopes_and_returns_code() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    session = _oauth_session()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(
            routes.OAuthSession,
            "get_by_state",
            new=AsyncMock(return_value=session),
        ),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=_client())),
        patch.object(
            routes,
            "consume_oauth_consent",
            new=AsyncMock(return_value=True),
        ) as consume,
        patch.object(
            routes,
            "create_authorization_code",
            new=AsyncMock(return_value=SimpleNamespace(code="granted-code")),
        ) as create_code,
    ):
        response = await routes.consent_authorize(_request(), "state-1", True)
        routes.UserConsent.grant.assert_awaited_once_with(
            tenant.uid, "user-1", "client-1", ["openid", "profile"]
        )
    assert response.headers["location"] == (
        "https://client.test/callback?code=granted-code&state=state-1"
    )
    consume.assert_awaited_once_with(
        session,
        granted_scope=["openid", "profile"],
        consented=True,
    )
    assert create_code.await_args.kwargs["scope"] == ["openid", "profile"]


@pytest.mark.asyncio
async def test_consent_authorize_handles_service_error() -> None:
    tenant = _tenant()
    session = _oauth_session()
    error = BadRequestError(
        error_code="invalid_client",
        detail="bad client",
        message={"en": "bad", "fa": "bad"},
    )
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(
            routes.OAuthSession,
            "get_by_state",
            new=AsyncMock(return_value=session),
        ),
        patch.object(routes, "validate_client", new=AsyncMock(side_effect=error)),
    ):
        response = await routes.consent_authorize(_request(), "state-1", True)
    assert "error=server_error" in response.headers["location"]
    assert "state=state-1" in response.headers["location"]


@pytest.mark.asyncio
async def test_device_authorization_delegates_to_device_service() -> None:
    tenant = _tenant()
    client = _client()
    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        patch(
            "apps.tenant.integration.device_code.create_device_authorization",
            new=AsyncMock(return_value=expected),
        ) as create,
    ):
        result = await routes.device_authorization(_request(), "client-1", "openid")
    assert result is expected
    create.assert_awaited_once_with(tenant=tenant, client=client, scope="openid")


@pytest.mark.asyncio
async def test_get_device_authorization_returns_pending_details() -> None:
    tenant = _tenant()
    auth = SimpleNamespace(
        client_id="client-1",
        user_code="ABCD-EFGH",
        scope=["openid"],
        expires_at=datetime.now(timezone.tz) + timedelta(minutes=5),
    )
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes.dependencies, "get_current_user", new=AsyncMock()),
        patch(
            "apps.tenant.integration.device_code.get_pending_by_user_code",
            new=AsyncMock(return_value=auth),
        ),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=_client())),
    ):
        result = await routes.get_device_authorization(_request(), "ABCD-EFGH")
    assert result.user_code == "ABCD-EFGH"
    assert result.client_name == "Coverage Client"
    assert 0 < result.expires_in <= 300


@pytest.mark.asyncio
async def test_decide_device_authorization_returns_granted_scope() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    auth = SimpleNamespace(
        client_id="client-1",
        user_code="ABCD-EFGH",
        scope=["openid", "profile"],
        granted_scope=["openid"],
        expires_at=datetime.now(timezone.tz) + timedelta(minutes=5),
    )
    data = OuathDeviceAuthorizationDecisionSchema(
        user_code="ABCD-EFGH", approve=True, scope=["openid"]
    )
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch(
            "apps.tenant.integration.device_code.approve_device_authorization",
            new=AsyncMock(return_value=auth),
        ) as approve,
        patch.object(routes, "validate_client", new=AsyncMock(return_value=_client())),
    ):
        result = await routes.decide_device_authorization(_request(), data)
    assert result.scope == ["openid"]
    approve.assert_awaited_once_with(
        tenant=tenant,
        user=user,
        user_code="ABCD-EFGH",
        approve=True,
        granted_scope=["openid"],
    )


@pytest.mark.asyncio
async def test_token_client_credentials_uses_form_client_id_fallback() -> None:
    tenant = _tenant()
    request = _request(form={"client_id": "form-client"})
    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "exchange_service_account_client_credentials",
            new=AsyncMock(return_value=expected),
        ) as exchange,
    ):
        result = await routes.token(
            **_token_kwargs(
                GrantType.CLIENT_CREDENTIALS,
                request=request,
                client_id=None,
                scope="read write",
            )
        )
    assert result is expected
    exchange.assert_awaited_once_with(
        tenant=tenant,
        client_id="form-client",
        client_secret="secret-value",
        scope="read write",
    )


@pytest.mark.asyncio
async def test_token_device_code_delegates() -> None:
    expected = object()
    client = _client()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=_tenant())),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        patch(
            "apps.tenant.integration.device_code.exchange_device_code",
            new=AsyncMock(return_value=expected),
        ) as exchange,
    ):
        result = await routes.token(
            **_token_kwargs(GrantType.DEVICE_CODE, device_code="device-secret")
        )
    assert result is expected
    assert exchange.await_args.kwargs["device_code"] == "device-secret"


@pytest.mark.asyncio
async def test_token_authorization_code_exchanges_and_creates_tokens() -> None:
    tenant = _tenant()
    client = _client()
    user = SimpleNamespace(uid="user-1")
    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes,
            "exchange_authorization_code",
            new=AsyncMock(return_value=(user, ["openid"], "nonce-1")),
        ) as exchange,
        patch.object(
            routes, "create_tokens", new=AsyncMock(return_value=expected)
        ) as create,
    ):
        result = await routes.token(
            **_token_kwargs(
                GrantType.AUTHORIZATION_CODE,
                code="auth-code",
                redirect_uri="https://client.test/callback",
                code_verifier="verifier",
            )
        )
    assert result is expected
    exchange.assert_awaited_once_with(
        code="auth-code",
        client=client,
        tenant=tenant,
        redirect_uri="https://client.test/callback",
        code_verifier="verifier",
    )
    create.assert_awaited_once_with(
        client=client,
        user=user,
        tenant=tenant,
        scope=["openid"],
        nonce="nonce-1",
    )


@pytest.mark.asyncio
async def test_token_refresh_and_unsupported_grants() -> None:
    tenant = _tenant()
    client = _client()
    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes, "refresh_access_token", new=AsyncMock(return_value=expected)
        ) as refresh,
    ):
        result = await routes.token(
            **_token_kwargs(GrantType.REFRESH_TOKEN, refresh_token="refresh-token")
        )
    assert result is expected
    refresh.assert_awaited_once_with(
        refresh_token="refresh-token", client=client, tenant=tenant
    )


@pytest.mark.asyncio
async def test_userinfo_requires_bearer_and_returns_service_result() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.userinfo(_request(headers={"Authorization": "Basic abc"}))
    assert exc.value.error_code == "invalid_authorization_header"

    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "get_user_info", new=AsyncMock(return_value=expected)
        ) as get_info,
    ):
        result = await routes.userinfo(
            _request(headers={"Authorization": "Bearer access-token"})
        )
    assert result is expected
    get_info.assert_awaited_once_with("access-token", tenant)


@pytest.mark.asyncio
async def test_introspect_validates_secret_and_delegates() -> None:
    tenant = _tenant()
    client = _client()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.introspect(_request(), "token", None, "client-1", "wrong")
    assert exc.value.error_code == "invalid_client"

    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_client",
            new=AsyncMock(return_value=_client(client_type="public")),
        ),
        patch.object(
            routes, "introspect_token", new=AsyncMock(return_value=expected)
        ) as introspect_token,
    ):
        result = await routes.introspect(
            _request(), "token", "access_token", "client-1", None
        )
    assert result is expected
    introspect_token.assert_awaited_once_with("token", tenant)


@pytest.mark.asyncio
async def test_revoke_validates_secret_succeeds_and_wraps_failures() -> None:
    tenant = _tenant()
    client = _client()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        pytest.raises(UnauthorizedError),
    ):
        await routes.revoke(_request(), "token", None, "client-1", None)

    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        patch.object(routes, "revoke_token", new=AsyncMock()) as revoke_token,
    ):
        result = await routes.revoke(
            _request(), "token", None, "client-1", "secret-value"
        )
    assert result == {"status": "success"}
    revoke_token.assert_awaited_once_with("token", client, tenant)

    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "validate_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes,
            "revoke_token",
            new=AsyncMock(side_effect=RuntimeError("store unavailable")),
        ),
        pytest.raises(ServiceUnavailableError) as exc,
    ):
        await routes.revoke(_request(), "token", None, "client-1", "secret-value")
    assert exc.value.error_code == "server_error"


@pytest.mark.asyncio
async def test_register_client_endpoint_uses_current_tenant_and_user() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    registration = ClientRegistrationRequestSchema(
        client_name="Coverage Client",
        redirect_uris=["https://client.test/callback"],
    )
    expected = object()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(
            routes, "register_client", new=AsyncMock(return_value=expected)
        ) as register,
    ):
        result = await routes.register_client_endpoint(_request(), registration)
    assert result is expected
    register.assert_awaited_once_with(registration, tenant, user)


@pytest.mark.asyncio
async def test_get_client_owner_and_registration_token_access() -> None:
    tenant = _tenant()
    client = _client()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes,
            "ClientRegistrationResponseSchema",
            side_effect=lambda **kwargs: SimpleNamespace(**kwargs),
        ),
    ):
        response = await routes.get_client(_request(), "client-1")
    assert response.client_id == "client-1"
    assert response.client_secret == "***"

    client.user_id = "other-user"
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes,
            "ClientRegistrationResponseSchema",
            side_effect=lambda **kwargs: SimpleNamespace(**kwargs),
        ),
        patch.object(
            routes.PasswordHasherService,
            "verify_password",
            return_value=True,
        ),
    ):
        rat_response = await routes.get_client(
            _request(headers={"Authorization": "Bearer registration-token"}),
            "client-1",
        )
    assert rat_response.client_id == "client-1"


@pytest.mark.asyncio
async def test_get_client_rejects_missing_or_unauthorized_client() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=None)),
        pytest.raises(NotFoundError),
    ):
        await routes.get_client(_request(), "missing")

    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(
            routes,
            "get_oauth_client",
            new=AsyncMock(return_value=_client(user_id="other")),
        ),
        pytest.raises(ForbiddenError) as exc,
    ):
        await routes.get_client(_request(), "client-1")
    assert exc.value.error_code == "client_access_denied"


@pytest.mark.asyncio
async def test_list_clients_serializes_owned_clients() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    client = _client(created_at=None, registration_access_token=None)
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies, "get_current_user", new=AsyncMock(return_value=user)
        ),
        patch.object(
            routes, "list_oauth_clients", new=AsyncMock(return_value=[client])
        ) as list_oauth,
        patch.object(
            routes,
            "ClientRegistrationResponseSchema",
            side_effect=lambda **kwargs: SimpleNamespace(**kwargs),
        ),
    ):
        result = await routes.list_clients(_request(), is_active=True)
    assert len(result) == 1
    assert result[0].client_id_issued_at == 0
    assert result[0].registration_access_token == ""
    list_oauth.assert_awaited_once_with(tenant=tenant, user_id="user-1", is_active=True)


@pytest.mark.asyncio
async def test_update_client_updates_owned_client() -> None:
    tenant = _tenant()
    client = _client()
    updated = _client(client_name="Renamed", registration_access_token=None)
    data = ClientUpdateSchema(client_name="Renamed")
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes, "update_oauth_client", new=AsyncMock(return_value=updated)
        ) as update,
        patch.object(
            routes,
            "ClientRegistrationResponseSchema",
            side_effect=lambda **kwargs: SimpleNamespace(**kwargs),
        ),
    ):
        result = await routes.update_client(_request(), "client-1", data)
    assert result.client_name == "Renamed"
    assert result.registration_access_token == ""
    update.assert_awaited_once_with(
        tenant=tenant, client_id="client-1", client_name="Renamed"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client", "updated", "error_type"),
    [
        (None, None, NotFoundError),
        (_client(user_id="other"), None, ForbiddenError),
        (_client(), None, ServiceUnavailableError),
    ],
)
async def test_update_client_errors(
    client: object, updated: object, error_type: type[Exception]
) -> None:
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=_tenant())),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes, "update_oauth_client", new=AsyncMock(return_value=updated)
        ),
        pytest.raises(error_type),
    ):
        await routes.update_client(
            _request(), "client-1", ClientUpdateSchema(client_name="Renamed")
        )


@pytest.mark.asyncio
async def test_delete_client_deactivates_owned_client() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=_client())),
        patch.object(
            routes, "deactivate_oauth_client", new=AsyncMock(return_value=True)
        ) as deactivate,
    ):
        assert await routes.delete_client(_request(), "client-1") is None
    deactivate.assert_awaited_once_with(tenant=tenant, client_id="client-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client", "success", "error_type"),
    [
        (None, True, NotFoundError),
        (_client(user_id="other"), True, ForbiddenError),
        (_client(), False, ServiceUnavailableError),
    ],
)
async def test_delete_client_errors(
    client: object, success: bool, error_type: type[Exception]
) -> None:
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=_tenant())),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes, "deactivate_oauth_client", new=AsyncMock(return_value=success)
        ),
        pytest.raises(error_type),
    ):
        await routes.delete_client(_request(), "client-1")


@pytest.mark.asyncio
async def test_rotate_client_secret_returns_new_secret() -> None:
    tenant = _tenant()
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=_client())),
        patch.object(
            routes,
            "regenerate_client_secret",
            new=AsyncMock(return_value="new-secret"),
        ),
    ):
        result = await routes.rotate_client_secret(_request(), "client-1")
    assert result == {
        "client_id": "client-1",
        "client_secret": "new-secret",
        "message": "Client secret rotated successfully",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client", "secret", "error_type"),
    [
        (None, "new-secret", NotFoundError),
        (_client(user_id="other"), "new-secret", ForbiddenError),
        (_client(), None, ServiceUnavailableError),
    ],
)
async def test_rotate_client_secret_errors(
    client: object, secret: str | None, error_type: type[Exception]
) -> None:
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=_tenant())),
        patch.object(
            routes.dependencies,
            "get_current_user",
            new=AsyncMock(return_value=SimpleNamespace(uid="user-1")),
        ),
        patch.object(routes, "get_oauth_client", new=AsyncMock(return_value=client)),
        patch.object(
            routes, "regenerate_client_secret", new=AsyncMock(return_value=secret)
        ),
        pytest.raises(error_type),
    ):
        await routes.rotate_client_secret(_request(), "client-1")


async def _authorize_with_stored_consent(
    *, covered: bool, scopes: list[str]
) -> tuple[object, AsyncMock, AsyncMock, MagicMock]:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    client = _client()
    client.require_consent = True
    session = SimpleNamespace(save=AsyncMock())
    handle = AsyncMock(
        return_value=RedirectResponse("ir.getmirza.flow:/oauth?code=xyz")
    )
    covers = AsyncMock(return_value=covered)
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(return_value=(client, scopes)),
        ),
        patch.object(
            routes.dependencies,
            "get_current_user_optional",
            new=AsyncMock(return_value=user),
        ),
        patch.object(routes.UserConsent, "covers", new=covers),
        patch.object(
            routes.OAuthSession, "get_by_state", new=AsyncMock(return_value=None)
        ),
        patch.object(routes, "_handle_authorized_user", new=handle),
        patch.object(
            routes.OAuthSession, "create_session", return_value=session
        ) as create_session,
    ):
        response = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "client-1",
            "https://client.test/callback",
            " ".join(scopes),
            "state_1234567890123456",
            None,
            "S256",
            None,
            None,
            None,
        )
    return response, handle, covers, create_session


@pytest.mark.asyncio
async def test_authorize_requires_consent_on_first_login() -> None:
    response, handle, covers, create_session = await _authorize_with_stored_consent(
        covered=False, scopes=["openid"]
    )
    assert response.headers["location"].startswith("https://frontend.test/consent")
    handle.assert_not_awaited()
    create_session.assert_called_once()
    covers.assert_awaited_once_with("tenant-1", "user-1", "client-1", ["openid"])


@pytest.mark.asyncio
async def test_authorize_skips_consent_when_already_granted() -> None:
    response, handle, _, create_session = await _authorize_with_stored_consent(
        covered=True, scopes=["openid"]
    )
    assert response.headers["location"] == "ir.getmirza.flow:/oauth?code=xyz"
    handle.assert_awaited_once()
    create_session.assert_not_called()


@pytest.mark.asyncio
async def test_authorize_requires_reconsent_when_scopes_increase() -> None:
    response, handle, _, _ = await _authorize_with_stored_consent(
        covered=False, scopes=["openid", "write"]
    )
    assert response.headers["location"].startswith("https://frontend.test/consent")
    handle.assert_not_awaited()


@pytest.mark.asyncio
async def test_authorize_prompt_consent_ignores_stored_consent() -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1")
    client = _client()
    client.require_consent = True
    covers = AsyncMock(return_value=True)
    with (
        patch.object(routes, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "validate_authorization_request",
            new=AsyncMock(return_value=(client, ["openid"])),
        ),
        patch.object(
            routes.dependencies,
            "get_current_user_optional",
            new=AsyncMock(return_value=user),
        ),
        patch.object(routes.UserConsent, "covers", new=covers),
        patch.object(
            routes.OAuthSession, "get_by_state", new=AsyncMock(return_value=None)
        ),
        patch.object(
            routes.OAuthSession,
            "create_session",
            return_value=SimpleNamespace(save=AsyncMock()),
        ),
    ):
        response = await routes.authorize(
            _request(),
            ResponseType.CODE,
            "client-1",
            "https://client.test/callback",
            "openid",
            "state_1234567890123456",
            None,
            "S256",
            None,
            "consent",
            None,
        )
    assert response.headers["location"].startswith("https://frontend.test/consent")
    covers.assert_not_awaited()
