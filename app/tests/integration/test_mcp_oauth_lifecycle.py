"""Exercise public-client OAuth through HTTP with real isolated persistence."""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from usso_jwt.schemas import UnverifiedJWT

from apps.tenant.integration import services
from apps.tenant.models import Tenant


async def _start(client: httpx.AsyncClient, *, consent: bool) -> tuple[str, str, str]:
    registration = await client.post(
        "/oauth/register",
        json={
            "client_name": "OAuth lifecycle test",
            "redirect_uris": ["https://client.example.test/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid read",
        },
    )
    assert registration.status_code == 201, registration.text
    client_id = registration.json()["client_id"]
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64
        .urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(24)
    authorization = await client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.example.test/callback",
            "scope": "openid read",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorization.is_redirect, authorization.text
    assert "consent" in authorization.headers["location"]
    decision = await client.post(
        "/oauth/consent", params={"state": state, "consent": consent}
    )
    assert decision.is_redirect, decision.text
    callback = parse_qs(urlsplit(decision.headers["location"]).query)
    assert callback["state"] == [state]
    if not consent:
        assert callback["error"] == ["access_denied"]
        assert "code" not in callback
        return client_id, verifier, ""
    assert "error" not in callback, callback
    return client_id, verifier, callback["code"][0]


@pytest.mark.asyncio
async def test_public_client_login_consent_refresh_and_revoke(
    authenticated_client: httpx.AsyncClient,
    initial_tenant: Tenant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Login fixture, consent, PKCE, renewal and revocation use the real app."""
    client = authenticated_client
    resource = "https://resource.example.test/mcp"
    monkeypatch.setattr(services.Settings, "dynamic_client_audiences", (resource,))
    client_id, verifier, code = await _start(client, consent=True)
    exchange = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": "https://client.example.test/callback",
        "code_verifier": "incorrect-verifier",
    }
    rejected = await client.post("/oauth/token", data=exchange)
    assert rejected.status_code == 400, rejected.text
    exchange["code_verifier"] = verifier
    issued = await client.post("/oauth/token", data=exchange)
    assert issued.status_code == 200, issued.text
    tokens = issued.json()
    claims = UnverifiedJWT(token=tokens["access_token"]).unverified_payload
    assert claims["iss"] == initial_tenant.primary_url
    assert not claims["iss"].endswith("/")
    assert resource in claims["aud"]
    assert set(claims["scopes"]) == {"openid", "read"}
    reused_code = await client.post("/oauth/token", data=exchange)
    assert reused_code.status_code == 400, reused_code.text
    userinfo = await client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert userinfo.status_code == 200, userinfo.text

    renewal = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": tokens["refresh_token"],
    }
    refreshed = await client.post("/oauth/token", data=renewal)
    assert refreshed.status_code == 200, refreshed.text
    current = refreshed.json()
    assert current["refresh_token"] != tokens["refresh_token"]
    reused_refresh = await client.post("/oauth/token", data=renewal)
    assert reused_refresh.status_code == 400, reused_refresh.text

    revoked = await client.post(
        "/oauth/revoke",
        data={"client_id": client_id, "token": current["refresh_token"]},
    )
    assert revoked.status_code == 200, revoked.text
    renewal["refresh_token"] = current["refresh_token"]
    blocked = await client.post("/oauth/token", data=renewal)
    assert blocked.status_code == 400, blocked.text
    userinfo = await client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {current['access_token']}"},
    )
    assert userinfo.status_code == 401, userinfo.text


@pytest.mark.asyncio
async def test_public_client_can_deny_consent(
    authenticated_client: httpx.AsyncClient,
) -> None:
    """Denying access returns an error without issuing an authorization code."""
    await _start(authenticated_client, consent=False)
