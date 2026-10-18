"""429 messages and OAuth browser error redirects."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.requests import Request

from apps.identity.auth.services import oauth
from server import rate_limiter
from server.exceptions import TooManyRequestsError


def _request(path: str, query: str = "", cookies: str = "") -> Request:
    headers = [(b"host", b"sso.example.test")]
    if cookies:
        headers.append((b"cookie", cookies.encode()))
    return Request({
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "query_string": query.encode(),
        "headers": headers,
        "server": ("sso.example.test", 443),
    })


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(default_redirect_url="/", allowed_return_domains=[]),
        domains=["getmirza.ir"],
        primary_domain="sso.example.test",
    )


@pytest.mark.asyncio
async def test_rate_limited_callback_raises_localized_429() -> None:
    callback = rate_limiter.rate_limited_callback(60)
    with pytest.raises(TooManyRequestsError) as exc:
        await callback(MagicMock(), MagicMock())
    assert exc.value.status_code == 429
    assert exc.value.data["retry_after"] == 60
    assert "60" in exc.value.message["fa"]
    assert "60" in exc.value.message["en"]


def test_auth_limit_raised() -> None:
    assert rate_limiter.MAX_REQUESTS["/auth"] >= 30


@pytest.mark.asyncio
async def test_authorize_429_redirects_to_return_url() -> None:
    request = _request(
        "/api/sso/v1/auth/oauth/google/authorize",
        "return_url=https%3A%2F%2Fgetmirza.ir%2Fauth%2Fsign-in%2F&handoff=true",
    )
    with patch(
        "apps.tenant.services.get_request_tenant",
        new=AsyncMock(return_value=_tenant()),
    ):
        response = await oauth.oauth_error_redirect(request, "too_many_requests", 60)
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert location.netloc == "getmirza.ir"
    assert parse_qs(location.query) == {
        "auth_error": ["too_many_requests"],
        "retry_after": ["60"],
    }


@pytest.mark.asyncio
async def test_callback_error_uses_return_url_cookie() -> None:
    request = _request(
        "/api/sso/v1/auth/oauth/telegram/callback",
        "code=x&state=y",
        'usso_oauth_return_url="https://getmirza.ir/auth/sign-in/"',
    )
    with patch(
        "apps.tenant.services.get_request_tenant",
        new=AsyncMock(return_value=_tenant()),
    ):
        response = await oauth.oauth_error_redirect(request, "invalid_state")
    location = urlsplit(response.headers["location"])
    assert location.netloc == "getmirza.ir"
    assert parse_qs(location.query) == {"auth_error": ["invalid_state"]}
    cleared = response.headers.getlist("set-cookie")
    assert any(c.startswith("usso_oidc_state=") for c in cleared)


@pytest.mark.asyncio
async def test_unsafe_return_url_falls_back_to_default() -> None:
    request = _request(
        "/api/sso/v1/auth/oauth/google/authorize",
        "return_url=https%3A%2F%2Fevil.test%2F",
    )
    with patch(
        "apps.tenant.services.get_request_tenant",
        new=AsyncMock(return_value=_tenant()),
    ):
        response = await oauth.oauth_error_redirect(request, "too_many_requests")
    assert response.headers["location"].startswith("/?auth_error=")


@pytest.mark.asyncio
async def test_non_oauth_paths_keep_json_errors() -> None:
    request = _request("/api/sso/v1/auth/login")
    assert await oauth.oauth_error_redirect(request, "too_many_requests") is None
