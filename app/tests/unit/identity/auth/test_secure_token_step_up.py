"""Secure step-up via passkey (one step, no captcha) and fresh OAuth re-login."""

from types import SimpleNamespace
from unittest import mock

import pytest

from apps.identity.auth import routes
from apps.identity.auth.enums import AuthSecret
from apps.identity.auth.services import oauth
from server.exceptions import BadRequestError, UnauthorizedError


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        uid="t1",
        access_auth=lambda _request: SimpleNamespace(uid="u1"),
        secrets=SimpleNamespace(
            oauth_secrets={
                "google": SimpleNamespace(
                    discovery_url="https://accounts.google.com/.well-known/openid-configuration"
                ),
                "telegram": SimpleNamespace(
                    discovery_url="https://oauth.telegram.org/.well-known/openid-configuration"
                ),
            }
        ),
        config=SimpleNamespace(default_redirect_url=None),
    )


def _request(cookies: dict[str, str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        url=SimpleNamespace(hostname="sso.example.test"),
        headers={"origin": "https://example.test"},
        cookies=cookies or {},
    )


ASSERTION = {
    "type": "public-key",
    "id": "cred",
    "rawId": "cred",
    "response": {"clientDataJSON": "x", "authenticatorData": "x", "signature": "x"},
}


# ---------------------------------------------------------------- passkey


def test_passkey_step_up_routes_have_no_captcha_dependency() -> None:
    """Passkey step-up must not require captcha."""
    for route in routes.router_limited.routes:
        if getattr(route, "path", "").endswith("/secure-token/passkey"):
            names = {
                getattr(dep.call, "__name__", type(dep.call).__name__)
                for dep in route.dependant.dependencies
            }
            assert "check_captcha" not in names
            break
    else:
        pytest.fail("secure-token/passkey route not registered")


@pytest.mark.asyncio
async def test_passkey_challenge_is_scoped_to_signed_in_user() -> None:
    generate = mock.AsyncMock(return_value={"challenge": "c"})
    with (
        mock.patch.object(
            routes, "get_request_tenant", mock.AsyncMock(return_value=_tenant())
        ),
        mock.patch(
            "apps.identity.user.credential_services.generate_authentication_challenge",
            generate,
        ),
    ):
        result = await routes.secure_token_passkey_challenge(_request())
    assert result == {"challenge": "c"}
    assert generate.await_args.kwargs["user_id"] == "u1"


@pytest.mark.asyncio
async def test_passkey_step_up_issues_secure_token_in_one_step() -> None:
    user = SimpleNamespace(uid="u1")
    issue = mock.MagicMock(return_value="response")
    with (
        mock.patch.object(
            routes, "get_request_tenant", mock.AsyncMock(return_value=_tenant())
        ),
        mock.patch(
            "apps.identity.user.credential_services.verify_authentication_passkey",
            mock.AsyncMock(return_value=user),
        ),
        mock.patch.object(routes, "_secure_token_response", issue),
    ):
        result = await routes.secure_token_passkey(
            _request(), routes.PasskeyAssertion.model_validate(ASSERTION)
        )
    assert result == "response"
    assert issue.call_args.kwargs["amr"] == [AuthSecret.WEBAUTHN.value]
    assert issue.call_args.kwargs["user"] is user


@pytest.mark.asyncio
async def test_passkey_step_up_rejects_another_users_passkey() -> None:
    with (
        mock.patch.object(
            routes, "get_request_tenant", mock.AsyncMock(return_value=_tenant())
        ),
        mock.patch(
            "apps.identity.user.credential_services.verify_authentication_passkey",
            mock.AsyncMock(return_value=SimpleNamespace(uid="someone-else")),
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.secure_token_passkey(
            _request(), routes.PasskeyAssertion.model_validate(ASSERTION)
        )
    assert exc.value.error_code == "secure_step_up_failed"


@pytest.mark.asyncio
async def test_passkey_step_up_requires_session() -> None:
    tenant = _tenant()
    tenant.access_auth = lambda _request: None
    with (
        mock.patch.object(
            routes, "get_request_tenant", mock.AsyncMock(return_value=tenant)
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes.secure_token_passkey(
            _request(), routes.PasskeyAssertion.model_validate(ASSERTION)
        )
    assert exc.value.error_code == "authentication_required"


# ---------------------------------------------------------------- oauth


def test_oauth_never_opens_a_secure_session() -> None:
    """Policy: only OTP and passkey may issue a secure token."""
    tenant = _tenant()
    assert not oauth.supports_oauth_step_up(
        "google", tenant.secrets.oauth_secrets["google"]
    )
    assert not oauth.supports_oauth_step_up(
        "telegram", tenant.secrets.oauth_secrets["telegram"]
    )
    assert not oauth.supports_oauth_step_up("google", None)


@pytest.mark.parametrize(
    ("auth_time", "fresh"),
    [
        (1000, True),
        (1000 - 300, True),
        (1000 - 301, False),
        (None, False),
        (True, False),
        (2000, False),
    ],
)
def test_fresh_oauth_authentication_window(auth_time: object, fresh: bool) -> None:
    userinfo = {} if auth_time is None else {"auth_time": auth_time}
    assert oauth.is_fresh_oauth_authentication(userinfo, now=1000) is fresh


@pytest.mark.asyncio
async def test_step_up_session_forces_fresh_provider_login() -> None:
    secret = SimpleNamespace(
        discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        client_id="cid",
        scopes=["openid"],
    )
    with (
        mock.patch.object(oauth, "resolve_provider_secret", return_value=secret),
        mock.patch.object(oauth, "fetch_oidc_config", mock.AsyncMock(return_value={})),
        mock.patch.object(
            oauth, "generate_oauth_redirect_uri", return_value="https://cb"
        ),
        mock.patch.object(
            oauth, "_auth_options", return_value=(False, "client_secret_post")
        ),
        mock.patch.object(
            oauth,
            "_validated_oidc_endpoint",
            mock.AsyncMock(return_value="https://accounts.google.com/o/oauth2/auth"),
        ),
    ):
        normal = await oauth.create_oauth_session(
            tenant=SimpleNamespace(), provider="google"
        )
        step_up = await oauth.create_oauth_session(
            tenant=SimpleNamespace(), provider="google", step_up=True
        )
    assert "prompt=login" not in normal.authorization_url
    assert "prompt=login" in step_up.authorization_url
    assert "max_age=0" in step_up.authorization_url


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["telegram", "google"])
async def test_authorize_step_up_rejects_every_provider(provider: str) -> None:
    with (
        mock.patch.object(
            routes, "get_request_tenant", mock.AsyncMock(return_value=_tenant())
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await routes.oauth_authorize(_request(), provider, step_up=True)
    assert exc.value.error_code == "step_up_not_supported"


def _identity() -> oauth.OAuthIdentity:
    return oauth.OAuthIdentity(
        identifier_type="email", identifier="a@example.test", method=AuthSecret.OAUTH
    )


@pytest.mark.asyncio
async def test_oauth_step_up_issues_secure_token_for_same_fresh_user() -> None:
    now = int(routes.datetime.now(routes.timezone.tz).timestamp())
    issue = mock.MagicMock(return_value=routes.Response())
    with (
        mock.patch(
            "apps.identity.user.services.find_user",
            mock.AsyncMock(return_value=SimpleNamespace(uid="u1")),
        ),
        mock.patch.object(routes, "_secure_token_response", issue),
        mock.patch.object(routes, "sanitize_return_url", return_value=None),
    ):
        await routes._oauth_step_up_response(
            request=_request(),
            tenant=_tenant(),
            identity=_identity(),
            userinfo={"auth_time": now},
        )
    assert issue.call_args.kwargs["amr"] == [AuthSecret.OAUTH.value]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("found_uid", "auth_time_offset", "code"),
    [
        ("someone-else", 0, "secure_step_up_failed"),
        (None, 0, "secure_step_up_failed"),
        ("u1", -3600, "secure_step_up_not_fresh"),
    ],
)
async def test_oauth_step_up_rejects_other_user_or_stale_login(
    found_uid: str | None, auth_time_offset: int, code: str
) -> None:
    now = int(routes.datetime.now(routes.timezone.tz).timestamp())
    found = SimpleNamespace(uid=found_uid) if found_uid else None
    with (
        mock.patch(
            "apps.identity.user.services.find_user", mock.AsyncMock(return_value=found)
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await routes._oauth_step_up_response(
            request=_request(),
            tenant=_tenant(),
            identity=_identity(),
            userinfo={"auth_time": now + auth_time_offset},
        )
    assert exc.value.error_code == code


# ---------------------------------------------------------------- methods


@pytest.mark.asyncio
async def test_secure_token_methods_lists_available_step_ups() -> None:
    identifiers = [
        SimpleNamespace(
            type="phone", identifier="09120000000", is_active=True, verified_at=1
        ),
        SimpleNamespace(
            type="email", identifier="a@x.test", is_active=True, verified_at=None
        ),
        SimpleNamespace(
            type="telegram_id", identifier="42", is_active=True, verified_at=1
        ),
    ]
    query = mock.MagicMock()
    query.to_list = mock.AsyncMock(return_value=identifiers)
    user = SimpleNamespace(
        get_credentials=mock.AsyncMock(side_effect=[["passkey"], ["oauth-cred"]])
    )
    with (
        mock.patch.object(
            routes, "get_request_tenant", mock.AsyncMock(return_value=_tenant())
        ),
        mock.patch(
            "apps.identity.user.models.UserIdentifier.get_query", return_value=query
        ),
        mock.patch.object(routes.User, "get_item", mock.AsyncMock(return_value=user)),
    ):
        result = await routes.secure_token_methods(_request())
    assert result == {
        "passkey": True,
        "otp": [{"type": "phone", "identifier": "09120000000"}],
        "oauth": [],
    }
