"""Coverage for auth URL, magic-link, and remaining messaging branches."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.datastructures import URL

from apps.identity.auth.enums import AuthIdentifier, AuthSecret, AuthStep
from apps.identity.auth.schemas import MagicLinkRequest, OTPRequest
from apps.identity.auth.services import basics, magic_link
from apps.identity.auth.services import message as message_services
from apps.tenant.messaging.enums import MessageChannelType


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://app.example.test/path", "https://app.example.test"),
        (URL("http://api.example.test/a"), "https://api.example.test"),
        ("http://localhost:8000/path", "http://localhost:8000"),
        ("https://localhost:8443/path", "https://localhost:8443"),
    ],
)
def test_get_tenant_url_explicit_urls(url: str | URL, expected: str) -> None:
    assert (
        basics.get_tenant_url(SimpleNamespace(primary_url="fallback"), url) == expected
    )


def test_get_tenant_url_falls_back_to_primary_url() -> None:
    assert basics.get_tenant_url(SimpleNamespace(primary_url="https://sso.test")) == (
        "https://sso.test"
    )


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "",
        "javascript:alert(1)",
        "DATA:text/plain,x",
        "file:/tmp/a",
        "about:blank",
    ],
)
def test_sanitize_origin_rejects_empty_and_dangerous(origin: str | None) -> None:
    assert basics.sanitize_origin(origin) is None


@pytest.mark.parametrize(
    "origin",
    ["bad host", "host/path", "host?x=1", "-bad.test", "bad_.test", "example.test:"],
)
def test_sanitize_origin_rejects_invalid_characters(origin: str) -> None:
    assert basics.sanitize_origin(origin) is None


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("https://example.test", "example.test"),
        ("http://localhost:8000", "localhost:8000"),
        ("127.0.0.1:3000", "127.0.0.1:3000"),
        ("sub-domain.example.test", "sub-domain.example.test"),
    ],
)
def test_sanitize_origin_accepts_hosts(origin: str, expected: str) -> None:
    assert basics.sanitize_origin(origin) == expected


def _magic_tenant() -> MagicMock:
    tenant = MagicMock()
    tenant.config.auth.magic_link_timeout = 600
    tenant.secrets.keys = [SimpleNamespace(public_pem="tenant-public-key")]
    tenant.secrets.trusted_identity_providers = {}
    return tenant


def _jwt_patches(issuer: str, payload: dict) -> tuple[MagicMock, MagicMock]:
    unverified = MagicMock()
    unverified.return_value.unverified_payload = {"iss": issuer}
    verified = MagicMock()
    verified.return_value.payload = payload
    return unverified, verified


def test_magic_link_payload_trusts_tenant_issuer() -> None:
    tenant = _magic_tenant()
    unverified, verified = _jwt_patches("https://sso.test", {"sub": "u1"})
    with (
        patch.object(magic_link, "get_tenant_url", return_value="https://sso.test"),
        patch.object(magic_link, "UnverifiedJWT", unverified),
        patch.object(magic_link, "JWT", verified),
        patch.object(magic_link, "JWTConfig") as config,
    ):
        result = magic_link.magic_link_payload("token", tenant)
    assert result == ({"sub": "u1"}, "tenant-public-key", None, 600)
    config.assert_called_once_with(
        maximum_age=600,
        issuer="https://sso.test",
        audience="https://sso.test",
        key="tenant-public-key",
    )
    verified.return_value.verify.assert_called_once_with()


def test_magic_link_payload_trusts_configured_identity_provider() -> None:
    tenant = _magic_tenant()
    tenant.secrets.trusted_identity_providers = {
        "https://idp.test": SimpleNamespace(
            key="idp-key", jwks_url="https://idp.test/jwks", maximum_age=90
        )
    }
    unverified, verified = _jwt_patches("https://idp.test", {"sub": "u2"})
    with (
        patch.object(magic_link, "get_tenant_url", return_value="https://sso.test"),
        patch.object(magic_link, "UnverifiedJWT", unverified),
        patch.object(magic_link, "JWT", verified),
        patch.object(magic_link, "JWTConfig") as config,
        patch.object(magic_link, "validate_public_url_sync"),
    ):
        result = magic_link.magic_link_payload("token", tenant)
    assert result == ({"sub": "u2"}, "idp-key", "https://idp.test/jwks", 90)
    config.assert_called_once_with(
        maximum_age=90,
        issuer="https://idp.test",
        audience="https://sso.test",
        jwks_url="https://idp.test/jwks",
    )


def _tenant() -> MagicMock:
    tenant = MagicMock()
    tenant.uid = "tenant-1"
    tenant.primary_domain = "sso.test"
    tenant.primary_url = "https://sso.test"
    tenant.config.auth.magic_link_timeout = 600
    tenant.config.auth.otp_length = 6
    tenant.config.auth.otp_timeout = 300
    tenant.secrets.channel_configs = {
        "sms": object(),
        "bale": object(),
        "email": object(),
    }
    tenant.sign_jwt.return_value = "signed-token"
    return tenant


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier_type", "identifier", "claim"),
    [
        (AuthIdentifier.EMAIL, "new@example.com", "email"),
        (AuthIdentifier.PHONE, "09120000000", "phone"),
        (AuthIdentifier.USERNAME, "new_user", "username"),
        (AuthIdentifier.NATIONAL_ID, "0012345678", "national_id"),
    ],
)
async def test_send_magic_link_created_user_payload_fields(
    identifier_type: AuthIdentifier, identifier: str, claim: str
) -> None:
    tenant = _tenant()
    request = MagicLinkRequest(type=identifier_type, identifier=identifier)
    user = SimpleNamespace(uid="user-1")
    with (
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, True)),
        ),
        patch.object(message_services.time, "time", return_value=1000),
        patch.object(
            message_services.messaging_services, "asend", new=AsyncMock()
        ) as send,
    ):
        await message_services.send_magic_link(
            tenant=tenant, origin="app.test", data=request
        )
    payload = tenant.sign_jwt.call_args.args[0]
    assert payload[claim] == request.identifier
    assert payload["sub"] == request.identifier
    assert payload["exp"] == 1600
    assert payload["jti"]
    assert send.await_args.kwargs["to"] == request.identifier
    assert "signed-token" in send.await_args.kwargs["context"]["magic_link"]


@pytest.mark.asyncio
async def test_send_magic_link_existing_user_prefers_email_identifier() -> None:
    tenant = _tenant()
    request = MagicLinkRequest(type=AuthIdentifier.USERNAME, identifier="requested")
    user = SimpleNamespace(
        get_identifiers=AsyncMock(
            return_value=[
                SimpleNamespace(type=AuthIdentifier.PHONE, identifier="09120000000"),
                SimpleNamespace(
                    type=AuthIdentifier.EMAIL, identifier="saved@example.com"
                ),
            ]
        )
    )
    with (
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, False)),
        ),
        patch.object(
            message_services.messaging_services, "asend", new=AsyncMock()
        ) as send,
    ):
        await message_services.send_magic_link(
            tenant=tenant, origin="app.test", data=request
        )
    assert tenant.sign_jwt.call_args.args[0]["email"] == "saved@example.com"
    assert send.await_args.kwargs["to"] == "saved@example.com"


@pytest.mark.asyncio
async def test_send_magic_link_existing_user_falls_back_to_request() -> None:
    tenant = _tenant()
    request = MagicLinkRequest(type=AuthIdentifier.USERNAME, identifier="requested")
    user = SimpleNamespace(
        get_identifiers=AsyncMock(
            return_value=[
                SimpleNamespace(type=AuthIdentifier.PHONE, identifier="09120000000")
            ]
        )
    )
    with (
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, False)),
        ),
        patch.object(
            message_services.messaging_services, "asend", new=AsyncMock()
        ) as send,
    ):
        await message_services.send_magic_link(
            tenant=tenant, origin="app.test", data=request
        )
    assert tenant.sign_jwt.call_args.args[0]["username"] == "requested"
    assert send.await_args.kwargs["to"] == "requested"


def _otp_query() -> tuple[MagicMock, MagicMock]:
    query = MagicMock()
    query.count = AsyncMock(return_value=0)
    query.sort.return_value.first_or_none = AsyncMock(return_value=None)
    query.find.return_value.update_many = AsyncMock()
    credential = MagicMock()
    credential.save = AsyncMock()
    credential_cls = MagicMock(return_value=credential)
    credential_cls.get_query.return_value = query
    return credential_cls, credential


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("channel_type", "request_type", "expected_template", "expected_method"),
    [
        (
            MessageChannelType.BALE,
            AuthIdentifier.PHONE,
            "sms_otp",
            AuthSecret.PHONE_OTP,
        ),
        (
            MessageChannelType.EMAIL,
            AuthIdentifier.EMAIL,
            "email_otp",
            AuthSecret.EMAIL_OTP,
        ),
    ],
)
async def test_create_otp_channel_branches(
    channel_type: MessageChannelType,
    request_type: AuthIdentifier,
    expected_template: str,
    expected_method: AuthSecret,
) -> None:
    tenant = _tenant()
    identifier = (
        "user@example.com" if request_type == AuthIdentifier.EMAIL else "09120000000"
    )
    request = OTPRequest(
        type=request_type, identifier=identifier, channel_type=channel_type
    )
    channel = SimpleNamespace(channel_type=channel_type)
    user = SimpleNamespace(uid="user-1")
    credential_cls, credential = _otp_query()
    scheduled: list[object] = []

    def close_scheduled(coro: object) -> None:
        scheduled.append(coro)
        coro.close()

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=channel_type,
        ),
        patch.object(OTPRequest, "get_channel", return_value=channel),
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, True)),
        ),
        patch.object(message_services, "_generate_random_otp", return_value=42),
        patch.object(message_services, "Credential", credential_cls),
        patch.object(
            message_services, "_schedule_background_task", side_effect=close_scheduled
        ),
        patch.object(
            message_services.messaging_services, "asend", new=AsyncMock()
        ) as send,
    ):
        assert (
            await message_services.create_otp(otp_request=request, tenant=tenant) == 42
        )
    assert credential_cls.call_args.kwargs["method"] is expected_method
    assert message_services.PasswordHasherService().verify_password(
        credential_cls.call_args.kwargs["secret"], "000042"
    )
    assert send.call_args.kwargs["channel"] is channel_type
    assert send.call_args.kwargs["template_type"] == expected_template
    assert send.call_args.kwargs["to"] == request.identifier
    assert scheduled
    credential.save.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_create_otp_existing_identifier_loop_falls_back_to_request() -> None:
    tenant = _tenant()
    request = OTPRequest(
        type=AuthIdentifier.PHONE,
        identifier="09129999999",
        channel_type=MessageChannelType.BALE,
    )
    channel = SimpleNamespace(channel_type=MessageChannelType.BALE)
    user = SimpleNamespace(
        uid="user-1",
        get_identifiers=AsyncMock(
            return_value=[
                SimpleNamespace(
                    type=AuthIdentifier.EMAIL, identifier="user@example.com"
                )
            ]
        ),
    )
    credential_cls, _ = _otp_query()

    def close(coro: object) -> None:
        coro.close()

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=MessageChannelType.BALE,
        ),
        patch.object(OTPRequest, "get_channel", return_value=channel),
        patch.object(
            message_services,
            "find_or_create_user",
            new=AsyncMock(return_value=(user, False)),
        ),
        patch.object(message_services, "_generate_random_otp", return_value=1),
        patch.object(message_services, "Credential", credential_cls),
        patch.object(message_services, "_schedule_background_task", side_effect=close),
        patch.object(
            message_services.messaging_services, "asend", new=AsyncMock()
        ) as send,
    ):
        await message_services.create_otp(otp_request=request, tenant=tenant)
    assert send.call_args.kwargs["to"] == request.identifier


@pytest.mark.asyncio
async def test_schedule_background_task_runs_and_discards_task() -> None:
    completed: list[str] = []

    async def work() -> None:
        await asyncio.sleep(0)
        completed.append("done")

    message_services._schedule_background_task(work())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert completed == ["done"]
    assert not message_services._background_tasks


@pytest.mark.asyncio
async def test_schedule_background_task_logs_exceptions(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def boom() -> None:
        await asyncio.sleep(0)
        raise RuntimeError("otp_send_failed")

    with caplog.at_level(logging.ERROR):
        message_services._schedule_background_task(boom())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert not message_services._background_tasks
    assert any("Background messaging task failed" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_check_otp_needed_email_and_skip_branches() -> None:
    tenant = _tenant()
    email = SimpleNamespace(type=AuthIdentifier.EMAIL, identifier="user@example.com")
    user = SimpleNamespace(
        get_identifiers=AsyncMock(return_value=[email]),
        get_credentials=AsyncMock(return_value=[]),
    )
    step = AuthStep(methods=[AuthSecret.EMAIL_OTP])
    with (
        patch.object(message_services, "sanitize_origin", return_value=None),
        patch.object(message_services, "create_otp", new=AsyncMock()) as create,
    ):
        await message_services.check_otp_needed_and_send(step, user, tenant)
    assert create.await_args.kwargs["otp_request"].identifier == "user@example.com"

    active = SimpleNamespace(method=AuthSecret.EMAIL_OTP)
    user.get_credentials = AsyncMock(return_value=[active])
    with patch.object(message_services, "create_otp", new=AsyncMock()) as create:
        await message_services.check_otp_needed_and_send(step, user, tenant)
        await message_services.check_otp_needed_and_send(
            step, user, tenant, amr=[AuthSecret.EMAIL_OTP]
        )
    create.assert_not_awaited()
