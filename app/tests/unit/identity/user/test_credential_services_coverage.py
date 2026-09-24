"""Focused coverage for passkey credential services."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.auth.enums import AuthIdentifier, AuthSecret
from apps.identity.user import credential_services as creds
from server.exceptions import UnauthorizedError
from utils import texttools


def _tenant() -> SimpleNamespace:
    return SimpleNamespace(
        uid="tenant-1",
        name="Acme",
        primary_domain="sso.example.test",
        primary_url="https://sso.example.test",
    )


def _assert_error(exc: pytest.ExceptionInfo[UnauthorizedError], code: str) -> None:
    assert exc.value.error_code == code


def test_get_rp_id_strips_port_and_uses_domain() -> None:
    assert creds.get_rp_id("localhost:8000", "ignored.test") == "localhost"
    assert creds.get_rp_id(None, "sso.example.test") == "sso.example.test"


def test_profile_display_name_from_schema_fields() -> None:
    profile = SimpleNamespace(
        profile_data=SimpleNamespace(first_name="Mahdi", last_name="Kiani")
    )
    assert creds._profile_display_name(profile, "fallback") == "Mahdi Kiani"
    assert creds._profile_display_name(None, "fallback") == "fallback"


def test_resolve_webauthn_rp_uses_page_origin_not_parent_domain() -> None:
    tenant = SimpleNamespace(
        primary_domain="usso.uln.me",
        primary_url="https://usso.uln.me",
        domains=["usso.uln.me", "panel.uln.me"],
    )
    rp_id, expected = creds.resolve_webauthn_rp(
        hostname="usso.uln.me",
        tenant=tenant,
        origin="https://panel.uln.me",
    )
    assert rp_id == "panel.uln.me"
    assert expected == "https://panel.uln.me"


def test_resolve_webauthn_rp_falls_back_without_origin() -> None:
    tenant = SimpleNamespace(
        primary_domain="usso.uln.me",
        primary_url="https://usso.uln.me",
        domains=["usso.uln.me"],
    )
    rp_id, expected = creds.resolve_webauthn_rp(
        hostname="usso.uln.me",
        tenant=tenant,
        origin=None,
    )
    assert rp_id == "usso.uln.me"
    assert expected == "https://usso.uln.me"


@pytest.mark.asyncio
async def test_register_passkey_returns_none_for_missing_user() -> None:
    with patch.object(
        creds.models.User, "get_item", new_callable=AsyncMock, return_value=None
    ):
        assert (
            await creds.register_passkey(_tenant(), SimpleNamespace(sub="missing"))
            is None
        )


@pytest.mark.asyncio
async def test_register_passkey_success() -> None:
    user = SimpleNamespace(
        user_id="user-1",
        user_name="fallback",
        get_identifiers=AsyncMock(
            return_value=[
                SimpleNamespace(type=AuthIdentifier.USERNAME, identifier="alice")
            ]
        ),
    )
    profile = SimpleNamespace(
        profile_data=SimpleNamespace(first_name="Alice", last_name="Example")
    )
    options = SimpleNamespace(challenge=b"register-challenge")
    tenant = _tenant()
    with (
        patch.object(
            creds.models.User, "get_item", new_callable=AsyncMock, return_value=user
        ),
        patch.object(
            creds.Profile,
            "get_by_user_id",
            new_callable=AsyncMock,
            return_value=profile,
        ),
        patch.object(
            creds.webauthn,
            "generate_registration_options",
            return_value=options,
        ) as generate,
        patch.object(
            creds.models.Credential, "create_item", new_callable=AsyncMock
        ) as create,
        patch.object(
            creds.webauthn.helpers,
            "options_to_json_dict",
            return_value={"challenge": "json"},
        ),
    ):
        result = await creds.register_passkey(
            tenant, SimpleNamespace(sub="user-1", user_name="data"), "host.test:8443"
        )

    assert result == {"challenge": "json"}
    assert generate.call_args.kwargs["rp_id"] == "host.test"
    assert generate.call_args.kwargs["user_name"] == "alice"
    assert generate.call_args.kwargs["user_display_name"] == "Alice Example"
    payload = create.await_args.args[0]
    assert payload["method"] == AuthSecret.WEBAUTHN
    assert payload["is_active"] is False


@pytest.mark.asyncio
async def test_verify_registration_passkey_missing_pending_credential() -> None:
    query = MagicMock()
    query.first_or_none = AsyncMock(return_value=None)
    with patch.object(creds.models.Credential, "get_query", return_value=query):
        result = await creds.verify_registration_passkey(
            _tenant(), SimpleNamespace(user_id="u1"), {}
        )
    assert result is None


@pytest.mark.asyncio
async def test_verify_registration_passkey_success() -> None:
    query = MagicMock()
    cred = SimpleNamespace(
        secret=texttools.base64url_encode(b"challenge"),
        meta_data=None,
        save=AsyncMock(),
    )
    cred.save.return_value = cred
    query.first_or_none = AsyncMock(return_value=cred)
    verification = SimpleNamespace(
        credential_id=b"credential-id",
        credential_public_key=b"public-key",
        sign_count=1,
    )
    user = SimpleNamespace(uid="user-uid", user_id="user-id", tenant_id="tenant-1")
    with (
        patch.object(creds.models.Credential, "get_query", return_value=query),
        patch.object(
            creds.webauthn, "verify_registration_response", return_value=verification
        ) as verify,
        patch.object(
            creds.models.UserIdentifier, "create_item", new_callable=AsyncMock
        ) as create_identifier,
    ):
        result = await creds.verify_registration_passkey(
            _tenant(), user, {"id": "response"}, "host.test:443"
        )

    assert result is cred
    assert verify.call_args.kwargs["expected_challenge"] == b"challenge"
    assert verify.call_args.kwargs["expected_rp_id"] == "host.test"
    assert create_identifier.await_args.args[0]["type"] == AuthIdentifier.PASSKEY_ID
    assert cred.is_active is True
    assert cred.expires_at is None
    assert cred.meta_data["credential_id"] == texttools.base64url_encode(
        b"credential-id"
    )
    assert cred.meta_data["sign_count"] == 1


@pytest.mark.asyncio
async def test_get_webauthn_credentials_none_empty_and_skips_missing_id() -> None:
    assert await creds.get_webauthn_credentials(None) is None
    empty_user = SimpleNamespace(get_credentials=AsyncMock(return_value=[]))
    assert await creds.get_webauthn_credentials(empty_user) is None
    missing_user = SimpleNamespace(
        get_credentials=AsyncMock(return_value=[SimpleNamespace(meta_data={})])
    )
    assert await creds.get_webauthn_credentials(missing_user) is None


@pytest.mark.asyncio
async def test_get_webauthn_credentials_builds_descriptors() -> None:
    encoded = texttools.base64url_encode(b"credential-id")
    user = SimpleNamespace(
        get_credentials=AsyncMock(
            return_value=[SimpleNamespace(meta_data={"credential_id": encoded})]
        )
    )
    descriptors = await creds.get_webauthn_credentials(user)
    assert descriptors is not None
    assert len(descriptors) == 1
    assert descriptors[0].id == b"credential-id"


@pytest.mark.asyncio
async def test_generate_authentication_challenge_stores_tenant() -> None:
    options = SimpleNamespace(challenge=b"auth-challenge")
    user = SimpleNamespace(uid="u1")
    with (
        patch.object(
            creds.models.User, "get_item", new_callable=AsyncMock, return_value=user
        ),
        patch.object(
            creds,
            "get_webauthn_credentials",
            new_callable=AsyncMock,
            return_value=["d"],
        ),
        patch.object(
            creds.webauthn, "generate_authentication_options", return_value=options
        ) as generate,
        patch.object(creds.redis, "set", new_callable=AsyncMock) as redis_set,
        patch.object(
            creds.webauthn.helpers,
            "options_to_json_dict",
            return_value={"challenge": "json"},
        ),
    ):
        result = await creds.generate_authentication_challenge(
            _tenant(), "u1", "host.test:8000"
        )

    assert result == {"challenge": "json"}
    assert generate.call_args.kwargs["allow_credentials"] == ["d"]
    redis_set.assert_awaited_once_with(
        creds._passkey_auth_challenge_key(b"auth-challenge"), "tenant-1", ex=300
    )


def _assertion(challenge: bytes = b"challenge") -> dict:
    client_data = texttools.base64url_encode(
        json.dumps({"challenge": texttools.base64url_encode(challenge)}).encode()
    )
    return {"id": "passkey-id", "response": {"clientDataJSON": client_data}}


@pytest.mark.asyncio
async def test_verify_authentication_rejects_missing_and_invalid_client_data() -> None:
    with pytest.raises(UnauthorizedError) as missing:
        await creds.verify_authentication_passkey(_tenant(), {})
    _assert_error(missing, "passkey_invalid")

    with pytest.raises(UnauthorizedError) as invalid:
        await creds.verify_authentication_passkey(
            _tenant(), {"response": {"clientDataJSON": "not-json"}}
        )
    _assert_error(invalid, "passkey_invalid")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored", "expected"),
    [(None, "passkey_challenge_expired"), (b"other-tenant", "passkey_tenant_mismatch")],
)
async def test_verify_authentication_rejects_challenge_state(
    stored: bytes | None, expected: str
) -> None:
    with (
        patch.object(
            creds.redis, "getdel", new_callable=AsyncMock, return_value=stored
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await creds.verify_authentication_passkey(_tenant(), _assertion())
    _assert_error(exc, expected)


async def _verify_with_objects(
    *,
    identifier: object = ...,
    user: object = ...,
    credential: object = ...,
    verification_error: Exception | None = None,
) -> object:
    if identifier is ...:
        identifier = SimpleNamespace(user_id="user-uid")
    if user is ...:
        user = SimpleNamespace(uid="user-uid", tenant_id="tenant-1")
    if credential is ...:
        credential = SimpleNamespace(
            secret=texttools.base64url_encode(b"public-key"),
            meta_data={"credential_id": "passkey-id", "sign_count": 2},
            save=AsyncMock(),
        )
    with (
        patch.object(
            creds.redis, "getdel", new_callable=AsyncMock, return_value=b"tenant-1"
        ),
        patch.object(
            creds.models.UserIdentifier,
            "find_one",
            new_callable=AsyncMock,
            return_value=identifier,
        ),
        patch.object(
            creds.models.User, "get_item", new_callable=AsyncMock, return_value=user
        ),
        patch.object(
            creds.models.Credential,
            "find_one",
            new_callable=AsyncMock,
            return_value=credential,
        ),
        patch.object(
            creds.webauthn,
            "verify_authentication_response",
            side_effect=(verification_error if verification_error else None),
            return_value=(
                None if verification_error else SimpleNamespace(new_sign_count=3)
            ),
        ) as verify,
    ):
        result = await creds.verify_authentication_passkey(
            _tenant(), _assertion(), "host.test:443"
        )
    return result, verify, credential


@pytest.mark.asyncio
async def test_verify_authentication_rejects_missing_identifier() -> None:
    with pytest.raises(UnauthorizedError) as exc:
        await _verify_with_objects(identifier=None)
    _assert_error(exc, "passkey_not_found")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [None, SimpleNamespace(uid="user-uid", tenant_id="wrong")],
)
async def test_verify_authentication_rejects_missing_or_wrong_tenant_user(
    user: object,
) -> None:
    with pytest.raises(UnauthorizedError) as exc:
        await _verify_with_objects(user=user)
    _assert_error(exc, "user_not_found")


@pytest.mark.asyncio
async def test_verify_authentication_rejects_missing_credential() -> None:
    with pytest.raises(UnauthorizedError) as exc:
        await _verify_with_objects(credential=None)
    _assert_error(exc, "passkey_not_found")


@pytest.mark.asyncio
async def test_verify_authentication_wraps_verification_errors() -> None:
    with pytest.raises(UnauthorizedError) as exc:
        await _verify_with_objects(verification_error=ValueError("bad assertion"))
    _assert_error(exc, "passkey_verification_failed")


@pytest.mark.asyncio
async def test_verify_authentication_success() -> None:
    user, verify, credential = await _verify_with_objects()
    assert user.uid == "user-uid"
    assert verify.call_args.kwargs["expected_rp_id"] == "host.test"
    assert verify.call_args.kwargs["credential_current_sign_count"] == 2
    assert credential.meta_data["sign_count"] == 3
    credential.save.assert_awaited_once()
