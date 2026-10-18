"""Direct-handler branch coverage for authentication routes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Response
from starlette.datastructures import URL
from usso.user import TokenType

from apps.identity.auth import routes
from apps.identity.auth.enums import AuthIdentifier, AuthSecret, LoginStatus
from apps.identity.auth.schemas import (
    LoginRequest,
    OTPRequest,
    QRApproveRequest,
    RefreshRequest,
    SecureTokenRequest,
    WorkspaceLoginRequest,
)
from apps.identity.user.models import User
from server.exceptions import BadRequestError, UnauthorizedError


def _request(
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    url: str = "https://login.example.test/auth",
) -> SimpleNamespace:
    return SimpleNamespace(
        headers=headers or {}, cookies=cookies or {}, url=URL(url), client=None
    )


def _tenant(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "uid": "tenant-1",
        "config": SimpleNamespace(
            cookie_header_config=SimpleNamespace(header_or_cookie="header"),
            default_redirect_url="https://app.example.test/home",
            auth=object(),
        ),
        "secrets": SimpleNamespace(oauth_secrets={"github": object()}),
        "temporary_auth": MagicMock(return_value="temporary-payload"),
        "optional_user": MagicMock(return_value="temporary-payload"),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _flow(
    *, user: object | None = None, next_step: object | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        user=user or SimpleNamespace(uid="user-1"),
        status=LoginStatus.COMPLETED,
        amr=["password"],
        next_step=next_step,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("prefer_cookie", [False, True])
async def test_login_attempt_header_and_cookie_responses(prefer_cookie: bool) -> None:
    request = _request(headers={"origin": "https://app.example.test"})
    tenant = _tenant()
    user = User.model_construct(uid="user-1", tenant_id="tenant-1")
    attempt = SimpleNamespace(
        user=user,
        status=LoginStatus.CHALLENGE_REQUIRED,
        next_step=None,
        otp_delivery={},
    )
    payloads = {TokenType.ACCESS: SimpleNamespace(token="temporary-token")}
    attach = MagicMock()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "resolve_login_attempt", new=AsyncMock(return_value=attempt)
        ),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(
            routes, "sanitize_origin", return_value="https://app.example.test"
        ),
        patch.object(routes, "_auto_send_otp", new=AsyncMock()) as auto_otp,
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=prefer_cookie,
        ) as cookie_preferred,
        patch(
            "apps.identity.auth.services.token.attach_auth_cookies_to_response",
            new=attach,
        ),
    ):
        response = await routes.login_attempt(request, SimpleNamespace())

    assert response.status_code == 200
    assert (b"temporary-token" in response.body) is (not prefer_cookie)
    assert cookie_preferred.call_count == 2
    auto_otp.assert_awaited_once_with(attempt, tenant, "https://app.example.test")
    if prefer_cookie:
        attach.assert_called_once()
    else:
        attach.assert_not_called()


@pytest.mark.asyncio
async def test_login_processes_wrapped_request_and_sends_next_otp() -> None:
    request = _request(headers={"user-agent": "pytest", "origin": "https://app"})
    tenant = _tenant()
    login_request = LoginRequest(
        type=AuthIdentifier.USERNAME,
        identifier="alice",
        method=AuthSecret.PASSWORD,
        secret="secret",
    )
    wrapped = SimpleNamespace(login_request=login_request)
    next_step = object()
    flow = _flow(next_step=next_step)
    payloads = {TokenType.ACCESS: object()}
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "process_login_flow", new=AsyncMock(return_value=flow)
        ) as process,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(routes, "maybe_attach_secure_token") as attach_secure,
        patch.object(routes, "check_otp_needed_and_send", new=AsyncMock()) as send_otp,
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=expected),
        ),
    ):
        result = await routes.login(request, wrapped)

    assert result is expected
    assert process.await_args.kwargs["login_request"] is login_request
    assert process.await_args.kwargs["temporary_payload"] == "temporary-payload"
    send_otp.assert_awaited_once_with(
        next_step=next_step,
        user=flow.user,
        tenant=tenant,
        origin="https://app",
        amr=flow.amr,
    )
    attach_secure.assert_called_once()


@pytest.mark.asyncio
async def test_signin_delegates_unwrapped_login_request() -> None:
    request = _request()
    login_request = object()
    data = SimpleNamespace(login_request=login_request)
    expected = object()
    with patch.object(routes, "login", new=AsyncMock(return_value=expected)) as login:
        assert await routes.signin(request, data) is expected
    login.assert_awaited_once_with(request=request, data=login_request)


@pytest.mark.asyncio
async def test_refresh_cookie_builds_response() -> None:
    request = _request()
    response = Response()
    refresh_payload = object()
    session = object()
    refresh_auth = MagicMock(return_value=refresh_payload)
    tenant = _tenant(refresh_auth=refresh_auth)
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "check_session_validity", new=AsyncMock(return_value=session)
        ),
        patch.object(routes, "build_refresh_response", return_value=expected) as build,
    ):
        assert await routes.refresh_cookie(request, response) is expected
    build.assert_called_once_with(
        request=request, tenant=tenant, payload=refresh_payload, session=session
    )


@pytest.mark.asyncio
async def test_refresh_body_decodes_token_and_builds_response() -> None:
    request = _request()
    refresh_payload = object()
    session = object()
    refresh_auth = MagicMock()
    refresh_auth.user_data_from_token.return_value = refresh_payload
    tenant = _tenant(refresh_auth=refresh_auth)
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "check_session_validity", new=AsyncMock(return_value=session)
        ),
        patch.object(routes, "build_refresh_response", return_value=expected),
    ):
        result = await routes.refresh_body(
            request, Response(), RefreshRequest(refresh_token="refresh-token")
        )
    assert result is expected
    refresh_auth.user_data_from_token.assert_called_once_with(
        "refresh-token", raise_exception=True, expected_token_type="refresh"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", [routes.refresh_cookie, routes.refresh_body])
async def test_refresh_failures_delete_refresh_cookies(handler: object) -> None:
    request = _request()
    response = MagicMock(spec=Response)
    error = UnauthorizedError(
        error_code="invalid_refresh", detail="bad", message={"en": "bad"}
    )
    tenant = _tenant(refresh_auth=MagicMock(side_effect=error))
    tenant.refresh_auth.user_data_from_token.side_effect = error
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError),
    ):
        if handler is routes.refresh_body:
            await routes.refresh_body(
                request, response, RefreshRequest(refresh_token="refresh-token")
            )
        else:
            await routes.refresh_cookie(request, response)
    assert response.delete_cookie.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("body_token", ["body-token", None])
async def test_workspace_login_accepts_body_or_cookie_refresh(
    body_token: str | None,
) -> None:
    request = _request(headers={"user-agent": "pytest"})
    refresh_payload = object()
    refresh_auth = MagicMock(return_value=refresh_payload)
    refresh_auth.user_data_from_token.return_value = refresh_payload
    tenant = _tenant(refresh_auth=refresh_auth)
    session = object()
    expected = object()
    data = WorkspaceLoginRequest(workspace_id="workspace-1", refresh_token=body_token)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "check_session_validity", new=AsyncMock(return_value=session)
        ),
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes,
            "build_workspace_switch_response",
            new=AsyncMock(return_value=expected),
        ) as build,
    ):
        assert await routes.workspace_login(request, Response(), data) is expected
    assert build.await_args.kwargs["workspace_id"] == "workspace-1"
    assert build.await_args.kwargs["payload"] is refresh_payload
    if body_token:
        refresh_auth.user_data_from_token.assert_called_once()
    else:
        refresh_auth.assert_called_once_with(request)


@pytest.mark.asyncio
async def test_workspace_login_requires_refresh_payload() -> None:
    tenant = _tenant(refresh_auth=MagicMock(return_value=None))
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.workspace_login(
            _request(),
            Response(),
            WorkspaceLoginRequest(workspace_id="workspace-1"),
        )
    assert exc.value.error_code == "refresh_token_required"


@pytest.mark.asyncio
async def test_magic_link_rejects_payload_without_identifier() -> None:
    with (
        patch.object(
            routes, "get_request_tenant", new=AsyncMock(return_value=_tenant())
        ),
        patch.object(
            routes,
            "magic_link_payload",
            return_value=({}, "pem", "jwks", 60),
        ),
        patch.object(routes, "consume_magic_link", new=AsyncMock()),
        patch.object(routes, "determine_identifier_type", return_value=(None, None)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.login_by_magic_link(_request(), Response(), "token")
    assert exc.value.error_code == "invalid_token"


@pytest.mark.asyncio
async def test_magic_link_completes_login_flow() -> None:
    request = _request(headers={"user-agent": "pytest"})
    tenant = _tenant()
    flow = _flow()
    payloads = {TokenType.ACCESS: object()}
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "magic_link_payload",
            return_value=({"email": "alice@example.com"}, "pem", "jwks", 60),
        ),
        patch.object(routes, "consume_magic_link", new=AsyncMock()),
        patch.object(
            routes,
            "determine_identifier_type",
            return_value=(AuthIdentifier.EMAIL, "alice@example.com"),
        ),
        patch.object(
            routes, "process_login_flow", new=AsyncMock(return_value=flow)
        ) as process,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(routes, "maybe_attach_secure_token") as attach_secure,
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=expected),
        ),
    ):
        assert (
            await routes.login_by_magic_link(request, Response(), "token") is expected
        )
    login_request = process.await_args.kwargs["login_request"]
    assert login_request.method is AuthSecret.MAGIC_LINK
    assert login_request.identifier == "alice@example.com"
    attach_secure.assert_called_once()


@pytest.mark.asyncio
async def test_generate_passkey_for_temporary_user() -> None:
    request = _request(url="https://login.example.test/auth/passkey")
    tenant = _tenant(
        optional_user=MagicMock(return_value=SimpleNamespace(user_id="user-1"))
    )
    generate = AsyncMock(return_value={"challenge": "abc"})
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch(
            "apps.identity.user.credential_services.generate_authentication_challenge",
            new=generate,
        ),
    ):
        assert await routes.generate_passkey(request) == {"challenge": "abc"}
    generate.assert_awaited_once_with(
        tenant=tenant,
        user_id="user-1",
        hostname="login.example.test",
        origin=None,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [True, False])
async def test_passkey_issues_login_response(active: bool) -> None:
    request = _request(headers={"user-agent": "pytest"})
    tenant = _tenant()
    user = User.model_construct(uid="user-1", tenant_id="tenant-1")
    assertion = SimpleNamespace(model_dump=MagicMock(return_value={"id": "passkey"}))
    payloads = {TokenType.ACCESS: object()}
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch(
            "apps.identity.user.credential_services.verify_authentication_passkey",
            new=AsyncMock(return_value=user),
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            new=AsyncMock(return_value=active),
        ),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ) as create,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(routes, "maybe_attach_secure_token"),
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=expected),
        ),
    ):
        assert await routes.passkey(request, assertion) is expected
    expected_status = (
        LoginStatus.COMPLETED if active else LoginStatus.VERIFICATION_REQUIRED
    )
    assert create.await_args.kwargs["login_flow_result"].status is expected_status


@pytest.mark.asyncio
async def test_qr_generate_wraps_service_payload() -> None:
    tenant = _tenant()
    payload = {
        "qr_token": "qr-token",
        "expires_in": 120,
        "qr_payload": "https://app/qr-token",
    }
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "create_qr_session", new=AsyncMock(return_value=payload)),
    ):
        result = await routes.qr_generate(_request())
    assert result.qr_token == "qr-token"


@pytest.mark.asyncio
async def test_qr_status_returns_pending_without_claiming() -> None:
    with (
        patch.object(
            routes, "get_request_tenant", new=AsyncMock(return_value=_tenant())
        ),
        patch.object(
            routes,
            "get_qr_session_status",
            new=AsyncMock(return_value={"status": "pending", "expires_in": 10}),
        ),
        patch.object(routes, "claim_approved_qr_user", new=AsyncMock()) as claim,
    ):
        result = await routes.qr_status(_request(), "qr-token")
    assert result.status == "pending"
    claim.assert_not_awaited()


@pytest.mark.asyncio
async def test_qr_status_approved_claims_and_issues_tokens() -> None:
    request = _request(headers={"user-agent": "pytest"})
    tenant = _tenant()
    user = User.model_construct(uid="user-1", tenant_id="tenant-1")
    payloads = {TokenType.ACCESS: object()}
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "get_qr_session_status",
            new=AsyncMock(return_value={"status": "approved", "user_id": "user-1"}),
        ),
        patch.object(
            routes, "claim_approved_qr_user", new=AsyncMock(return_value=user)
        ),
        patch(
            "apps.identity.auth.services.login_flow.activate_user_if_eligible",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(routes, "maybe_attach_secure_token"),
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=expected),
        ),
    ):
        assert await routes.qr_status(request, "qr-token") is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("found", [False, True])
async def test_qr_approve_requires_user_then_delegates(found: bool) -> None:
    request = _request()
    access_auth = MagicMock(return_value=SimpleNamespace(uid="user-1"))
    tenant = _tenant(access_auth=access_auth)
    user = SimpleNamespace(uid="user-1") if found else None
    approve = AsyncMock(return_value={"status": "denied"})
    data = QRApproveRequest(qr_token="qr-token", approve=False)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(routes, "approve_qr_session", new=approve),
    ):
        if not found:
            with pytest.raises(UnauthorizedError) as exc:
                await routes.qr_approve(request, data)
            assert exc.value.error_code == "user_not_found"
        else:
            assert await routes.qr_approve(request, data) == {"status": "denied"}
            approve.assert_awaited_once_with(
                tenant=tenant, user=user, qr_token="qr-token", approve=False
            )


@pytest.mark.asyncio
async def test_request_otp_sanitizes_origin_and_creates_otp() -> None:
    request = _request(headers={"origin": "https://app.example.test"})
    tenant = _tenant()
    data = OTPRequest(type=AuthIdentifier.EMAIL, identifier="alice@example.com")
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "sanitize_origin", return_value="https://app.example.test"
        ),
        patch.object(routes, "create_otp", new=AsyncMock()) as create,
    ):
        assert await routes.request_otp(request, data) == {"status": "success"}
    create.assert_awaited_once_with(
        otp_request=data, tenant=tenant, origin="https://app.example.test"
    )


@pytest.mark.asyncio
async def test_oauth_authorize_rejects_unknown_provider() -> None:
    with (
        patch.object(
            routes, "get_request_tenant", new=AsyncMock(return_value=_tenant())
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.oauth_authorize(_request(), "unknown")
    assert exc.value.error_code == "invalid_provider"


@pytest.mark.asyncio
@pytest.mark.parametrize("with_optional_cookies", [False, True])
async def test_oauth_authorize_sets_state_and_optional_cookies(
    with_optional_cookies: bool,
) -> None:
    tenant = _tenant()
    session = SimpleNamespace(
        authorization_url="https://provider.example/authorize",
        state="state-1",
        code_verifier="verifier" if with_optional_cookies else None,
        nonce="nonce-1",
    )
    safe_url = "https://app.example.test/after" if with_optional_cookies else None
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes, "create_oauth_session", new=AsyncMock(return_value=session)
        ),
        patch.object(routes, "sanitize_return_url", return_value=safe_url),
    ):
        response = await routes.oauth_authorize(_request(), "github")
    assert response.status_code == 307
    cookies = b"\n".join(
        value for key, value in response.raw_headers if key.lower() == b"set-cookie"
    )
    assert b"usso_oidc_state=state-1" in cookies
    assert (b"usso_oidc_verifier=verifier" in cookies) is with_optional_cookies
    # Invalid caller-provided or configured redirects must not be persisted.
    assert (b"usso_oauth_return_url=" in cookies) is with_optional_cookies


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "cookies", "error_code"),
    [
        ("unknown", {"usso_oidc_state": "state"}, "invalid_provider"),
        ("github", {}, "invalid_state"),
        ("github", {"usso_oidc_state": "different"}, "invalid_state"),
    ],
)
async def test_oauth_callback_rejects_provider_or_state(
    provider: str, cookies: dict[str, str], error_code: str
) -> None:
    with (
        patch.object(
            routes, "get_request_tenant", new=AsyncMock(return_value=_tenant())
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.oauth_callback(
            _request(cookies=cookies), Response(), provider, "state", "code"
        )
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
async def test_oauth_callback_rejects_missing_nonce() -> None:
    """OIDC callback requires the nonce cookie before exchanging the code."""
    with (
        patch.object(
            routes, "get_request_tenant", new=AsyncMock(return_value=_tenant())
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.oauth_callback(
            _request(cookies={"usso_oidc_state": "state"}),
            Response(),
            "github",
            "state",
            "code",
        )
    assert exc.value.error_code == "invalid_nonce"


def test_resolve_oauth_callback_identity_logs_and_reraises() -> None:
    """Unauthorized identity resolution is logged then re-raised."""
    err = UnauthorizedError(
        error_code="telegram_auth_invalid",
        detail="bad claims",
        message={"en": "bad", "fa": "بد"},
    )
    with (
        patch.object(routes, "resolve_oauth_identity", side_effect=err),
        patch.object(routes.logger, "warning") as warn,
        pytest.raises(UnauthorizedError) as exc,
    ):
        routes._resolve_oauth_callback_identity(
            provider="telegram",
            userinfo={"sub": "opaque", "aud": "1"},
            secrets_data=None,
        )
    assert exc.value is err
    warn.assert_called_once()
    assert "oauth_callback identity failed" in warn.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("redirect", [True, False])
async def test_oauth_callback_full_flow_and_cookie_cleanup(redirect: bool) -> None:
    request = _request(
        headers={"user-agent": "pytest"},
        cookies={
            "usso_oidc_state": "state",
            "usso_oidc_verifier": "verifier",
            "usso_oidc_nonce": "nonce",
            "usso_oauth_return_url": "https://app.example.test/after",
        },
    )
    tenant = _tenant()
    identity = SimpleNamespace(
        identifier="987654321",
        identifier_type=AuthIdentifier.TELEGRAM_ID,
        method=AuthSecret.TELEGRAM_TOKEN,
        name="Alice",
    )
    flow = _flow()
    payloads = {TokenType.ACCESS: object()}
    login_response = Response(content=b"login", media_type="application/json")
    login_response.set_cookie("usso-access-token", "access")
    safe_redirect = "https://app.example.test/after" if redirect else None
    tenant.config.default_redirect_url = None
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "exchange_oauth_code_for_userinfo",
            new=AsyncMock(return_value=("id-token", {"sub": "1"}, "jwks")),
        ) as exchange,
        patch.object(routes, "resolve_oauth_identity", return_value=identity),
        patch.object(routes, "create_oauth_credential", new=AsyncMock()) as credential,
        patch.object(
            routes, "process_login_flow", new=AsyncMock(return_value=flow)
        ) as process,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(routes, "maybe_attach_secure_token"),
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=login_response),
        ),
        patch.object(routes, "sanitize_return_url", return_value=safe_redirect),
    ):
        response = await routes.oauth_callback(
            request, Response(), "github", "state", "code"
        )

    exchange.assert_awaited_once()
    credential.assert_awaited_once()
    assert process.await_args.kwargs["telegram_verified"] is True
    assert process.await_args.kwargs["name"] == "Alice"
    if redirect:
        assert response.status_code == 307
        assert response.headers["location"] == safe_redirect
        assert any(
            key.lower() == b"set-cookie" and b"usso-access-token=access" in value
            for key, value in response.raw_headers
        )
    else:
        assert response is login_response
    cookie_headers = [
        value for key, value in response.raw_headers if key.lower() == b"set-cookie"
    ]
    assert sum(b"Max-Age=0" in value for value in cookie_headers) >= 3


@pytest.mark.asyncio
async def test_oauth_callback_email_oauth_sets_oauth_verified() -> None:
    """Non-Telegram OAuth identity sets oauth_verified on the login flow."""
    request = _request(
        cookies={
            "usso_oidc_state": "state",
            "usso_oidc_verifier": "verifier",
            "usso_oidc_nonce": "nonce",
        },
    )
    tenant = _tenant()
    tenant.config.default_redirect_url = None
    identity = SimpleNamespace(
        identifier="user@example.com",
        identifier_type=AuthIdentifier.EMAIL,
        method=AuthSecret.OAUTH,
        name=None,
    )
    flow = _flow()
    payloads = {TokenType.ACCESS: object()}
    login_response = Response(content=b"login", media_type="application/json")
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "exchange_oauth_code_for_userinfo",
            new=AsyncMock(
                return_value=(
                    "id-token",
                    {"email": "user@example.com"},
                    "jwks",
                )
            ),
        ),
        patch.object(routes, "resolve_oauth_identity", return_value=identity),
        patch.object(routes, "create_oauth_credential", new=AsyncMock()),
        patch.object(
            routes, "process_login_flow", new=AsyncMock(return_value=flow)
        ) as process,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(routes, "maybe_attach_secure_token"),
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=login_response),
        ),
        patch.object(routes, "sanitize_return_url", return_value=None),
    ):
        response = await routes.oauth_callback(
            request, Response(), "github", "state", "code"
        )
    assert response is login_response
    assert process.await_args.kwargs["oauth_verified"] is True
    assert "name" not in process.await_args.kwargs
    assert "telegram_verified" not in process.await_args.kwargs


def _secure_login_request() -> SecureTokenRequest:
    return SecureTokenRequest(
        type=AuthIdentifier.PHONE,
        identifier="+989120000000",
        method=AuthSecret.PHONE_OTP,
        secret="123456",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("prefer_cookie", [False, True])
async def test_issue_secure_token_returns_body_or_cookie(prefer_cookie: bool) -> None:
    request = _request()
    user = SimpleNamespace(uid="user-1")
    tenant = _tenant(access_auth=MagicMock(return_value=SimpleNamespace(uid="user-1")))
    secure_payload = SimpleNamespace(
        token="secure-token", model_dump=MagicMock(return_value={"sub": "user-1"})
    )
    attach = MagicMock()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "is_secure_method", return_value=True),
        patch(
            "apps.identity.user.services.find_user",
            new=AsyncMock(return_value=user),
        ),
        patch(
            "apps.identity.user.services.authenticate_user",
            new=AsyncMock(return_value=True),
        ),
        patch.object(
            routes, "create_secure_token_payload", return_value=secure_payload
        ),
        patch(
            "apps.identity.auth.services.token.is_cookie_auth_preferred",
            return_value=prefer_cookie,
        ),
        patch(
            "apps.identity.auth.services.token.attach_auth_cookies_to_response",
            new=attach,
        ),
    ):
        response = await routes.issue_secure_token(request, _secure_login_request())

    assert response.status_code == 200
    assert (b"secure-token" in response.body) is (not prefer_cookie)
    if prefer_cookie:
        attach.assert_called_once()
    else:
        attach.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("access_user", "secure_method", "found_uid", "authenticated", "error_code"),
    [
        (None, True, "user-1", True, "authentication_required"),
        ("user-1", False, "user-1", True, "secure_method_required"),
        ("user-1", True, "other-user", True, "secure_step_up_failed"),
        ("user-1", True, "user-1", False, "invalid_credentials"),
    ],
)
async def test_issue_secure_token_rejects_invalid_step_up(
    access_user: str | None,
    secure_method: bool,
    found_uid: str,
    authenticated: bool,
    error_code: str,
) -> None:
    access_payload = (
        SimpleNamespace(uid=access_user) if access_user is not None else None
    )
    tenant = _tenant(access_auth=MagicMock(return_value=access_payload))
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "is_secure_method", return_value=secure_method),
        patch(
            "apps.identity.user.services.find_user",
            new=AsyncMock(return_value=SimpleNamespace(uid=found_uid)),
        ),
        patch(
            "apps.identity.user.services.authenticate_user",
            new=AsyncMock(return_value=authenticated),
        ),
        pytest.raises((UnauthorizedError, BadRequestError)) as exc,
    ):
        await routes.issue_secure_token(_request(), _secure_login_request())
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
@pytest.mark.parametrize("has_existing_credential", [False, True])
async def test_set_password_creates_or_updates_credential(
    has_existing_credential: bool,
) -> None:
    tenant = _tenant()
    user = SimpleNamespace(uid="user-1", tenant_id="tenant-1")
    existing = SimpleNamespace(secret="old-hash", save=AsyncMock())
    created = SimpleNamespace(save=AsyncMock())
    query = SimpleNamespace(
        to_list=AsyncMock(return_value=[existing] if has_existing_credential else [])
    )
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes,
            "require_secure_token",
            return_value=SimpleNamespace(sub="user-1"),
        ),
        patch.object(User, "get_item", new=AsyncMock(return_value=user)),
        patch("apps.identity.user.models.Credential") as credential_model,
        patch(
            "apps.identity.auth.pass_validator.validate_password_policy",
            return_value=SimpleNamespace(is_valid=True, unmet_requirements=[]),
        ),
        patch("utils.hasher.PasswordHasherService") as hasher,
        patch(
            "apps.identity.auth.routes.AuthSession.revoke_user_sessions",
            new=AsyncMock(),
        ),
    ):
        credential_model.get_query.return_value = query
        credential_model.return_value = created
        hasher.return_value.hash_password.return_value = "new-hash"
        result = await routes.set_password(
            _request(), routes.ResetPasswordRequest(new_password="New-password-1")
        )

    assert result["status"] == "success"
    if has_existing_credential:
        assert existing.secret == "new-hash"
        existing.save.assert_awaited_once()
        credential_model.assert_not_called()
    else:
        credential_model.assert_called_once_with(
            tenant_id="tenant-1",
            user_id="user-1",
            method=AuthSecret.PASSWORD,
            secret="new-hash",
            is_active=True,
        )
        created.save.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user", "policy_valid", "error_code"),
    [
        (None, True, "secure_token_invalid"),
        (SimpleNamespace(uid="user-1", tenant_id="tenant-1"), False, "password_policy"),
    ],
)
async def test_set_password_rejects_invalid_user_or_policy(
    user: object | None, policy_valid: bool, error_code: str
) -> None:
    with (
        patch.object(
            routes, "get_request_tenant", new=AsyncMock(return_value=_tenant())
        ),
        patch.object(
            routes,
            "require_secure_token",
            return_value=SimpleNamespace(sub="user-1"),
        ),
        patch.object(User, "get_item", new=AsyncMock(return_value=user)),
        patch(
            "apps.identity.auth.pass_validator.validate_password_policy",
            return_value=SimpleNamespace(
                is_valid=policy_valid, unmet_requirements=["uppercase required"]
            ),
        ),
        pytest.raises((UnauthorizedError, BadRequestError)) as exc,
    ):
        await routes.set_password(
            _request(), routes.ResetPasswordRequest(new_password="weak")
        )
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
@pytest.mark.parametrize("display_name", [None, "Alice"])
async def test_login_by_telegram_completes_flow(display_name: str | None) -> None:
    request = _request(headers={"user-agent": "pytest"})
    oauth_secret = SimpleNamespace(
        client_id="telegram-client", discovery_url="https://telegram/.well-known"
    )
    tenant = _tenant(optional_user=MagicMock(return_value="temporary-payload"))
    login_request = _secure_login_request()
    flow = _flow()
    payloads = {TokenType.ACCESS: object()}
    expected = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "require_telegram_oauth", return_value=oauth_secret),
        patch(
            "apps.identity.auth.services.telegram.ensure_telegram_discovery",
            return_value=oauth_secret,
        ),
        patch(
            "apps.identity.auth.services.oauth.fetch_oidc_config",
            new=AsyncMock(return_value={"jwks_uri": "https://telegram/jwks"}),
        ),
        patch(
            "apps.identity.auth.services.oauth._validated_oidc_endpoint",
            new=AsyncMock(return_value="https://telegram/jwks"),
        ),
        patch.object(
            routes, "verify_telegram_id_token", return_value={"sub": "987654321"}
        ),
        patch.object(routes, "telegram_user_id_from_claims", return_value="987654321"),
        patch.object(
            routes, "build_telegram_login_request", return_value=login_request
        ),
        patch.object(routes, "telegram_display_name", return_value=display_name),
        patch.object(
            routes, "process_login_flow", new=AsyncMock(return_value=flow)
        ) as process,
        patch.object(routes, "get_client_ip", return_value="127.0.0.1"),
        patch.object(
            routes, "create_token_response", new=AsyncMock(return_value=payloads)
        ),
        patch.object(routes, "maybe_attach_secure_token"),
        patch.object(
            routes,
            "build_browser_login_response",
            new=AsyncMock(return_value=expected),
        ),
    ):
        result = await routes.login_by_telegram(
            request, routes.TelegramIdTokenSchema(id_token="id-token")
        )

    assert result is expected
    assert process.await_args.kwargs["temporary_payload"] == "temporary-payload"
    assert process.await_args.kwargs["telegram_verified"] is True
    if display_name:
        assert process.await_args.kwargs["name"] == display_name
    else:
        assert "name" not in process.await_args.kwargs


@pytest.mark.asyncio
async def test_secure_token_status_requires_access_session() -> None:
    tenant = _tenant(access_auth=MagicMock(return_value=None))
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.secure_token_status(_request())
    assert exc.value.error_code == "authentication_required"


@pytest.mark.asyncio
async def test_secure_token_status_reports_validity() -> None:
    tenant = _tenant(access_auth=MagicMock(return_value=SimpleNamespace(uid="user-1")))
    payload = SimpleNamespace(exp=999)
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "extract_secure_token", return_value=None),
    ):
        missing = await routes.secure_token_status(_request())
    assert missing == {"valid": False}

    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "extract_secure_token", return_value="tok"),
        patch.object(routes, "require_secure_token", return_value=payload),
    ):
        ok = await routes.secure_token_status(_request())
    assert ok == {"valid": True, "exp": 999}

    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "extract_secure_token", return_value="tok"),
        patch.object(
            routes,
            "require_secure_token",
            side_effect=UnauthorizedError(
                error_code="secure_token_invalid",
                detail="bad",
                message={"en": "bad", "fa": "bad"},
            ),
        ),
    ):
        invalid = await routes.secure_token_status(_request())
    assert invalid == {"valid": False}
