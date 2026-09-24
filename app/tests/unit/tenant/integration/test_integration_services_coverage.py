"""Focused unit coverage for OAuth2/OIDC integration services."""

import base64
import hashlib
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.tenant.integration import services
from apps.tenant.integration.schemas import Scope
from server.exceptions import BadRequestError, UnauthorizedError


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        primary_url="https://sso.test",
        config=SimpleNamespace(
            token=SimpleNamespace(access_timeout=900, refresh_timeout=2_592_000)
        ),
        sign_jwt=MagicMock(return_value="signed.jwt"),
    )


def _client(**kwargs: object) -> SimpleNamespace:
    values = {
        "client_id": "client-1",
        "is_active": True,
        "redirect_uris": ["https://app.test/callback"],
        "response_types": ["code"],
        "allowed_scopes": [Scope.OPENID, Scope.PROFILE, Scope.EMAIL],
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def _query(items: list[object]) -> MagicMock:
    query = MagicMock()
    query.to_list = AsyncMock(return_value=items)
    return query


@pytest.mark.asyncio
async def test_validate_client_rejects_missing_inactive_and_bad_redirect() -> None:
    tenant = _tenant()
    cases = [
        (None, None, "invalid_client_id"),
        (_client(is_active=False), None, "client_not_active"),
        (_client(), "https://evil.test/callback", "invalid_redirect_uri"),
    ]
    for client, redirect_uri, error_code in cases:
        with (
            patch.object(
                services, "get_oauth_client", new=AsyncMock(return_value=client)
            ),
            pytest.raises(BadRequestError) as exc,
        ):
            await services.validate_client("client-1", tenant, redirect_uri)
        assert exc.value.error_code == error_code

    client = _client()
    with patch.object(services, "get_oauth_client", new=AsyncMock(return_value=client)):
        assert (
            await services.validate_client(
                "client-1", tenant, "https://app.test/callback"
            )
            is client
        )


@pytest.mark.asyncio
async def test_validate_authorization_request_filters_and_defaults_scopes() -> None:
    client = _client()
    request = SimpleNamespace(
        client_id="client-1",
        redirect_uri="https://app.test/callback",
        response_type="code",
        scope="openid unknown profile",
        code_challenge="A" * 43,
        code_challenge_method="S256",
    )
    with patch.object(services, "validate_client", new=AsyncMock(return_value=client)):
        result_client, scopes = await services.validate_authorization_request(
            request, _tenant()
        )
    assert result_client is client
    assert scopes == ["openid", "profile"]

    request.scope = "unknown"
    with patch.object(services, "validate_client", new=AsyncMock(return_value=client)):
        _, scopes = await services.validate_authorization_request(request, _tenant())
    assert scopes == ["openid"]

    request.response_type = "token"
    with (
        patch.object(services, "validate_client", new=AsyncMock(return_value=client)),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.validate_authorization_request(request, _tenant())
    assert exc.value.error_code == "unsupported_response_type"


@pytest.mark.asyncio
async def test_create_authorization_code_revokes_old_codes() -> None:
    old = SimpleNamespace(is_used=False, save=AsyncMock())
    created = SimpleNamespace(save=AsyncMock())
    with (
        patch.object(services.AuthorizationCode, "find", return_value=_query([old])),
        patch.object(
            services.AuthorizationCode, "create_code", return_value=created
        ) as create,
    ):
        result = await services.create_authorization_code(
            _client(),
            SimpleNamespace(uid="user-1"),
            _tenant(),
            "https://app.test/callback",
            ["openid"],
            nonce="nonce",
        )
    assert result is created
    assert old.is_used is True
    old.save.assert_awaited_once()
    created.save.assert_awaited_once()
    assert create.call_args.kwargs["nonce"] == "nonce"


def test_validate_pkce_branches() -> None:
    services._validate_pkce(SimpleNamespace(code_challenge=None), None)

    auth_code = SimpleNamespace(
        uid="auth-code-1", code_challenge="challenge", code_challenge_method="plain"
    )
    with pytest.raises(BadRequestError) as required:
        services._validate_pkce(auth_code, None)
    assert required.value.error_code == "code_verifier_required"

    with pytest.raises(BadRequestError) as method_error:
        services._validate_pkce(auth_code, "challenge")
    assert method_error.value.error_code == "invalid_code_challenge_method"
    auth_code.code_challenge_method = "S256"
    with pytest.raises(BadRequestError) as invalid_s256:
        services._validate_pkce(auth_code, "wrong")
    assert invalid_s256.value.error_code == "invalid_code_verifier"

    verifier = "verifier"
    challenge = (
        base64
        .urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    auth_code.code_challenge_method = "S256"
    auth_code.code_challenge = challenge
    services._validate_pkce(auth_code, verifier)
    auth_code.code_challenge = "wrong"
    with pytest.raises(BadRequestError) as invalid_s256:
        services._validate_pkce(auth_code, verifier)
    assert invalid_s256.value.error_code == "invalid_code_verifier"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "error_code"),
    [
        ({"client_id": "other"}, "invalid_client_for_authorization_code"),
        ({"redirect_uri": "https://other.test/cb"}, "invalid_redirect_uri"),
        ({"is_used": True}, "authorization_code_already_used"),
    ],
)
async def test_exchange_authorization_code_rejects_mismatches(
    overrides: dict[str, object], error_code: str
) -> None:
    values = {
        "client_id": "client-1",
        "redirect_uri": "https://app.test/callback",
        "is_used": False,
        "code_challenge": None,
    }
    values.update(overrides)
    with (
        patch.object(
            services.AuthorizationCode,
            "get_by_code",
            new=AsyncMock(return_value=SimpleNamespace(**values)),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.exchange_authorization_code(
            "code", _client(), _tenant(), "https://app.test/callback"
        )
    assert exc.value.error_code == error_code


@pytest.mark.asyncio
async def test_exchange_authorization_code_missing_code_user_and_success() -> None:
    with (
        patch.object(
            services.AuthorizationCode, "get_by_code", new=AsyncMock(return_value=None)
        ),
        pytest.raises(BadRequestError) as missing,
    ):
        await services.exchange_authorization_code(
            "bad", _client(), _tenant(), "https://app.test/callback"
        )
    assert missing.value.error_code == "invalid_authorization_code"

    auth_code = SimpleNamespace(
        uid="auth-code-1",
        client_id="client-1",
        redirect_uri="https://app.test/callback",
        is_used=False,
        code_challenge=None,
        user_id="user-1",
        scope=["openid"],
        nonce="nonce",
        save=AsyncMock(),
    )
    collection = MagicMock(
        update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1))
    )
    with (
        patch.object(
            services.AuthorizationCode,
            "get_by_code",
            new=AsyncMock(return_value=auth_code),
        ),
        patch.object(
            services.AuthorizationCode,
            "get_pymongo_collection",
            return_value=collection,
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing_user,
    ):
        await services.exchange_authorization_code(
            "code", _client(), _tenant(), "https://app.test/callback"
        )
    assert missing_user.value.error_code == "user_not_found"

    user = SimpleNamespace(uid="user-1")
    auth_code.is_used = False
    with (
        patch.object(
            services.AuthorizationCode,
            "get_by_code",
            new=AsyncMock(return_value=auth_code),
        ),
        patch.object(
            services.AuthorizationCode,
            "get_pymongo_collection",
            return_value=collection,
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
    ):
        assert await services.exchange_authorization_code(
            "code", _client(), _tenant(), "https://app.test/callback"
        ) == (user, ["openid"], "nonce")
    assert auth_code.is_used is True


def test_create_service_account_access_token_builds_claims() -> None:
    tenant = _tenant()
    response = services.create_service_account_access_token(
        tenant=tenant,
        client_id="key-1",
        scopes=["read:item"],
        workspace_id="ws-1",
        user_id="user-1",
        created_by="admin-1",
        sub_type="api_key",
        aud="api",
    )
    assert response.access_token == "signed.jwt"
    assert response.expires_in == 900
    assert response.scope == "read:item"
    claims = tenant.sign_jwt.call_args.args[0]
    assert claims["aud"] == "api"
    assert claims["sub_type"] == "api_key"
    assert claims["exp"] - claims["iat"] == 900


def test_oauth_client_secret_rejects_plaintext_storage() -> None:
    """Legacy plaintext client secrets fail closed instead of authenticating."""
    plaintext = _client(client_type="confidential", client_secret="client-secret")
    assert services.verify_oauth_client_secret(plaintext, "client-secret") is False

    hashed = _client(client_type="confidential", client_secret="$argon2id$encoded")
    with patch.object(
        services.PasswordHasherService,
        "verify_password",
        return_value=True,
    ):
        assert services.verify_oauth_client_secret(hashed, "client-secret") is True


@pytest.mark.asyncio
async def test_oauth_consent_is_consumed_atomically() -> None:
    session = SimpleNamespace(
        uid="session-1",
        tenant_id="tenant-1",
        user_id="user-1",
        is_consented=False,
        is_consumed=False,
        granted_scope=[],
    )
    collection = MagicMock(
        update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1))
    )
    with patch.object(
        services.OAuthSession,
        "get_pymongo_collection",
        return_value=collection,
    ):
        assert await services.consume_oauth_consent(
            session,
            granted_scope=["openid"],
            consented=True,
        )
    assert session.is_consumed is True
    assert session.is_consented is True
    assert session.granted_scope == ["openid"]

    collection.update_one.return_value = SimpleNamespace(modified_count=0)
    with patch.object(
        services.OAuthSession,
        "get_pymongo_collection",
        return_value=collection,
    ):
        assert not await services.consume_oauth_consent(
            session,
            granted_scope=["openid"],
            consented=True,
        )


def test_grant_requested_scopes_allows_subset_and_rejects_extra() -> None:
    assert services._grant_requested_scopes(requested=[], allowed=["read:item"]) == [
        "read:item"
    ]
    with patch("usso.authorization.has_subset_scope", return_value=True):
        assert services._grant_requested_scopes(
            requested=["read:item"], allowed=["read:*"]
        ) == ["read:item"]
    with (
        patch("usso.authorization.has_subset_scope", return_value=False),
        pytest.raises(BadRequestError) as exc,
    ):
        services._grant_requested_scopes(
            requested=["delete:item"], allowed=["read:item"]
        )
    assert exc.value.error_code == "invalid_scope"


@pytest.mark.asyncio
async def test_service_account_credentials_missing_and_agent_paths() -> None:
    with pytest.raises(UnauthorizedError) as missing:
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(), client_id="agent-1", client_secret=None, scope=None
        )
    assert missing.value.error_code == "invalid_client"

    agent = SimpleNamespace(
        uid="agent-1",
        is_active=False,
        scopes=["read:item"],
        workspace_id="ws-1",
        user_id="user-1",
        created_by="user-1",
    )
    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.models.Agent.find_one",
            new=AsyncMock(return_value=agent),
        ),
        pytest.raises(UnauthorizedError) as inactive,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(), client_id="agent-1", client_secret="secret", scope=None
        )
    assert inactive.value.error_code == "agent_not_active"

    agent.is_active = True
    expected = MagicMock()
    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.models.Agent.find_one",
            new=AsyncMock(return_value=agent),
        ),
        patch(
            "apps.identity.agent.services.verify_agent_client_secret", return_value=True
        ),
        patch.object(
            services, "create_service_account_access_token", return_value=expected
        ) as create,
    ):
        assert (
            await services.exchange_service_account_client_credentials(
                tenant=_tenant(),
                client_id="agent-1",
                client_secret="secret",
                scope="read:item",
            )
            is expected
        )
    assert create.call_args.kwargs["sub_type"] == "agent"


@pytest.mark.asyncio
async def test_service_account_api_key_and_unknown_client_paths() -> None:
    """API keys apply request controls before issuance; unknown IDs are rejected."""
    api_key = SimpleNamespace(
        uid="key-1",
        scopes=["read:item"],
        workspace_id="ws-1",
        user_id="user-1",
        created_by="admin-1",
    )
    expected = MagicMock()
    client_ip_var = MagicMock()
    client_ip_var.get.return_value = "127.0.0.1"
    user_agent_var = MagicMock()
    user_agent_var.get.return_value = "pytest"
    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=api_key),
        ),
        patch("apps.identity.api_key.services.verify_client_secret", return_value=True),
        patch("apps.identity.api_key.services._validate_api_key_state") as validate,
        patch(
            "apps.identity.api_key.services.enforce_api_key_ip_whitelist"
        ) as whitelist,
        patch(
            "apps.identity.api_key.services.enforce_api_key_rate_limit",
            new=AsyncMock(),
        ) as rate_limit,
        patch(
            "apps.identity.api_key.services.record_api_key_usage", new=AsyncMock()
        ) as usage,
        patch("utils.request_context.client_ip_var", new=client_ip_var),
        patch("utils.request_context.user_agent_var", new=user_agent_var),
        patch.object(
            services, "create_service_account_access_token", return_value=expected
        ) as create,
    ):
        assert (
            await services.exchange_service_account_client_credentials(
                tenant=_tenant(),
                client_id="key-1",
                client_secret="secret",
                scope="read:item",
            )
            is expected
        )
    validate.assert_called_once_with(api_key)
    whitelist.assert_called_once_with(api_key, client_ip="127.0.0.1")
    rate_limit.assert_awaited_once_with(api_key)
    usage.assert_awaited_once_with(api_key, client_ip="127.0.0.1", user_agent="pytest")
    assert create.call_args.kwargs["sub_type"] == "api_key"

    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=api_key),
        ),
        patch(
            "apps.identity.api_key.services.verify_client_secret", return_value=False
        ),
        pytest.raises(UnauthorizedError) as bad_secret,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(),
            client_id="key-1",
            client_secret="bad",
            scope=None,
        )
    assert bad_secret.value.error_code == "invalid_client"

    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.models.Agent.find_one",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError) as unknown,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(),
            client_id="missing",
            client_secret="secret",
            scope=None,
        )
    assert unknown.value.error_code == "invalid_client"


@pytest.mark.asyncio
async def test_service_account_rejects_bad_agent_secret() -> None:
    """An active agent still requires a valid client secret."""
    agent = SimpleNamespace(is_active=True)
    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.models.Agent.find_one",
            new=AsyncMock(return_value=agent),
        ),
        patch(
            "apps.identity.agent.services.verify_agent_client_secret",
            return_value=False,
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(),
            client_id="agent-1",
            client_secret="bad",
            scope=None,
        )
    assert exc.value.error_code == "invalid_client"


@pytest.mark.asyncio
async def test_service_account_api_key_and_invalid_client_paths() -> None:
    api_key = SimpleNamespace(
        uid="key-1",
        scopes=["read:item"],
        workspace_id="ws-1",
        user_id="user-1",
        created_by="admin-1",
    )
    expected = MagicMock()
    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=api_key),
        ),
        patch(
            "apps.identity.api_key.services.verify_client_secret",
            return_value=True,
        ),
        patch("apps.identity.api_key.services._validate_api_key_state") as validate,
        patch(
            "apps.identity.api_key.services.enforce_api_key_ip_whitelist"
        ) as whitelist,
        patch(
            "apps.identity.api_key.services.enforce_api_key_rate_limit",
            new=AsyncMock(),
        ) as rate_limit,
        patch(
            "apps.identity.api_key.services.record_api_key_usage",
            new=AsyncMock(),
        ) as record,
        patch("usso.authorization.has_subset_scope", return_value=True),
        patch.object(
            services, "create_service_account_access_token", return_value=expected
        ) as create,
    ):
        assert (
            await services.exchange_service_account_client_credentials(
                tenant=_tenant(),
                client_id="key-1",
                client_secret="secret",
                scope="read:item",
            )
            is expected
        )
    validate.assert_called_once_with(api_key)
    whitelist.assert_called_once()
    rate_limit.assert_awaited_once_with(api_key)
    record.assert_awaited_once()
    assert create.call_args.kwargs["sub_type"] == "api_key"

    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=api_key),
        ),
        patch(
            "apps.identity.api_key.services.verify_client_secret",
            return_value=False,
        ),
        pytest.raises(UnauthorizedError) as bad_secret,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(),
            client_id="key-1",
            client_secret="wrong",
            scope=None,
        )
    assert bad_secret.value.error_code == "invalid_client"

    agent = SimpleNamespace(uid="agent-1", is_active=True)
    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.models.Agent.find_one",
            new=AsyncMock(side_effect=[agent, None]),
        ),
        patch(
            "apps.identity.agent.services.verify_agent_client_secret",
            return_value=False,
        ),
        pytest.raises(UnauthorizedError) as bad_agent_secret,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(),
            client_id="agent-1",
            client_secret="wrong",
            scope=None,
        )
    assert bad_agent_secret.value.error_code == "invalid_client"

    with (
        patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "apps.identity.agent.models.Agent.find_one",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(UnauthorizedError) as unknown_client,
    ):
        await services.exchange_service_account_client_credentials(
            tenant=_tenant(),
            client_id="unknown",
            client_secret="secret",
            scope=None,
        )
    assert unknown_client.value.error_code == "invalid_client"


@pytest.mark.asyncio
async def test_create_tokens_revokes_existing_and_optionally_creates_id_token() -> None:
    old = SimpleNamespace(revoke_related_tokens=AsyncMock())
    access = SimpleNamespace(
        uid="access-1", raw_token="access", token="access-digest", save=AsyncMock()
    )
    refresh = SimpleNamespace(
        raw_token="refresh", refresh_token="refresh-digest", save=AsyncMock()
    )
    with (
        patch.object(services.OAuthToken, "find", return_value=_query([old])),
        patch.object(services.OAuthToken, "create_access_token", return_value=access),
        patch.object(services.OAuthToken, "create_refresh_token", return_value=refresh),
        patch.object(
            services, "create_id_token", new=AsyncMock(return_value="id")
        ) as create_id,
    ):
        response = await services.create_tokens(
            _client(), SimpleNamespace(uid="user-1"), _tenant(), ["openid"]
        )
    assert response.access_token == "access"
    assert response.refresh_token == "refresh"
    assert response.id_token == "id"
    assert access.refresh_token == "refresh-digest"
    assert access.save.await_count == 2
    old.revoke_related_tokens.assert_awaited_once()
    create_id.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_id_token_adds_profile_email_and_nonce_claims() -> None:
    user = SimpleNamespace(
        uid="user-1",
        name="Alice Example",
        get_username=AsyncMock(return_value="alice"),
        get_identifiers=AsyncMock(
            return_value=[
                SimpleNamespace(
                    type="email",
                    identifier="a@example.com",
                    verified_at=datetime.now(),
                )
            ]
        ),
    )
    tenant = _tenant()
    assert (
        await services.create_id_token(
            user,
            tenant,
            _client(),
            [Scope.PROFILE.value, Scope.EMAIL.value],
            nonce="nonce",
        )
        == "signed.jwt"
    )
    claims = tenant.sign_jwt.call_args.args[0]
    assert claims["given_name"] == "Alice"
    assert claims["family_name"] == "Example"
    assert claims["preferred_username"] == "alice"
    assert claims["email_verified"] is True
    assert claims["nonce"] == "nonce"


@pytest.mark.asyncio
async def test_refresh_access_token_errors_and_success() -> None:
    client = _client()
    tenant = _tenant()
    with (
        patch.object(
            services.OAuthToken,
            "get_by_refresh_token",
            new=AsyncMock(return_value=None),
        ),
        pytest.raises(BadRequestError) as invalid,
    ):
        await services.refresh_access_token("refresh", client, tenant)
    assert invalid.value.error_code == "invalid_refresh_token"

    token = SimpleNamespace(
        uid="refresh-1",
        client_id="other",
        user_id="user-1",
        scope=["openid"],
    )
    with (
        patch.object(
            services.OAuthToken,
            "get_by_refresh_token",
            new=AsyncMock(return_value=token),
        ),
        pytest.raises(BadRequestError) as wrong_client,
    ):
        await services.refresh_access_token("refresh", client, tenant)
    assert wrong_client.value.error_code == "invalid_client_for_refresh_token"

    token.client_id = "client-1"
    token.revoke_related_tokens = AsyncMock()
    with (
        patch.object(
            services.OAuthToken,
            "get_by_refresh_token",
            new=AsyncMock(return_value=token),
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as missing_user,
    ):
        await services.refresh_access_token("refresh", client, tenant)
    assert missing_user.value.error_code == "user_not_found"

    user = SimpleNamespace(uid="user-1")
    expected = MagicMock()
    collection = MagicMock(
        update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1))
    )
    with (
        patch.object(
            services.OAuthToken,
            "get_by_refresh_token",
            new=AsyncMock(return_value=token),
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            services.OAuthToken,
            "get_pymongo_collection",
            return_value=collection,
        ),
        patch.object(services, "create_tokens", new=AsyncMock(return_value=expected)),
    ):
        assert (
            await services.refresh_access_token("refresh", client, tenant) is expected
        )
    token.revoke_related_tokens.assert_awaited_once()


@pytest.mark.asyncio
async def test_introspect_token_inactive_and_active() -> None:
    tenant = _tenant()
    with patch.object(
        services.OAuthToken, "get_by_token", new=AsyncMock(return_value=None)
    ):
        assert not (await services.introspect_token("bad", tenant)).active

    expires = datetime.now() + timedelta(hours=1)
    token = SimpleNamespace(
        user_id="user-1",
        scope=["openid"],
        client_id="client-1",
        token_type=SimpleNamespace(value="Bearer"),
        expires_at=expires,
        uid="token-1",
    )
    with (
        patch.object(
            services.OAuthToken, "get_by_token", new=AsyncMock(return_value=token)
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
    ):
        assert not (await services.introspect_token("orphaned", tenant)).active

    user = SimpleNamespace(uid="user-1", get_username=AsyncMock(return_value="alice"))
    with (
        patch.object(
            services.OAuthToken, "get_by_token", new=AsyncMock(return_value=token)
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
    ):
        response = await services.introspect_token("access", tenant)
    assert response.active is True
    assert response.username == "alice"
    assert response.jti == "token-1"


@pytest.mark.asyncio
async def test_get_user_info_errors_and_maps_identifiers() -> None:
    tenant = _tenant()
    with (
        patch.object(
            services.OAuthToken, "get_by_token", new=AsyncMock(return_value=None)
        ),
        pytest.raises(UnauthorizedError) as invalid,
    ):
        await services.get_user_info("bad", tenant)
    assert invalid.value.error_code == "invalid_access_token"

    token = SimpleNamespace(user_id="user-1")
    with (
        patch.object(
            services.OAuthToken, "get_by_token", new=AsyncMock(return_value=token)
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(UnauthorizedError) as missing_user,
    ):
        await services.get_user_info("orphaned", tenant)
    assert missing_user.value.error_code == "user_not_found"

    user = SimpleNamespace(
        uid="user-1",
        name="Alice Example",
        get_username=AsyncMock(return_value="alice"),
        get_identifiers=AsyncMock(
            return_value=[
                SimpleNamespace(type="email", identifier="a@example.com"),
                SimpleNamespace(type="phone", identifier="989120000000"),
            ]
        ),
    )
    with (
        patch.object(
            services.OAuthToken, "get_by_token", new=AsyncMock(return_value=token)
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
    ):
        response = await services.get_user_info("access", tenant)
    assert response.email == "a@example.com"
    assert response.phone_number == "989120000000"
    assert response.family_name == "Example"


@pytest.mark.asyncio
async def test_register_client_and_revoke_token() -> None:
    request = SimpleNamespace(
        client_name="Example",
        redirect_uris=["https://app.test/callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
        logo_uri=None,
        client_uri=None,
        policy_uri=None,
        tos_uri=None,
    )
    client = SimpleNamespace(
        registration_access_token=None,
        save=AsyncMock(),
        model_dump=MagicMock(return_value={"client_id": "client-1"}),
    )
    response = MagicMock()
    client_cls = MagicMock(return_value=client)
    client_cls.generate_client_id.return_value = "client-1"
    client_cls.generate_client_secret.return_value = "secret"
    with (
        patch.object(services, "OAuthClient", client_cls),
        patch.object(services.secrets, "token_urlsafe", return_value="registration"),
        patch.object(
            services, "ClientRegistrationResponseSchema", return_value=response
        ),
    ):
        assert (
            await services.register_client(
                request, _tenant(), SimpleNamespace(uid="user-1")
            )
            is response
        )
    assert client.save.await_count == 2
    assert client.registration_access_token != "registration"

    token = SimpleNamespace(client_id="client-1", revoke_related_tokens=AsyncMock())
    with patch.object(
        services.OAuthToken, "get_by_token", new=AsyncMock(return_value=token)
    ):
        await services.revoke_token("access", _client(), _tenant())
    token.revoke_related_tokens.assert_awaited_once()

    token.revoke_related_tokens.reset_mock()
    token.client_id = "other"
    with patch.object(
        services.OAuthToken, "get_by_token", new=AsyncMock(return_value=token)
    ):
        await services.revoke_token("access", _client(), _tenant())
    token.revoke_related_tokens.assert_not_awaited()
