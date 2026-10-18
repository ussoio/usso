"""Focused unit coverage for KYC service helpers."""

import json
from datetime import date
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from usso.user import TokenType

from apps.identity.auth.enums import AuthIdentifier, LoginStatus
from apps.identity.kyc import services
from apps.identity.kyc.models import KYC
from apps.identity.kyc.schemas import KYCStatus


def _async_client(**methods: object) -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    for name, value in methods.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


def _kyc() -> KYC:
    return KYC.model_construct(
        uid="kyc-1",
        tenant_id="tenant-1",
        user_id="user-1",
        national_code="0012345678",
        birth_date=date(1991, 3, 21),
        phone="09120000000",
        status=KYCStatus.APPROVED,
    )


@pytest.mark.asyncio
async def test_activate_user_creates_identifier_and_deduplicates_roles() -> None:
    """Activation stores a verified national ID and adds required roles once."""
    user = SimpleNamespace(
        uid="user-1",
        tenant_id="tenant-1",
        roles=["user"],
        name=None,
        is_active=False,
        save=AsyncMock(return_value="saved-user"),
    )
    identifier = SimpleNamespace(save=AsyncMock())
    identifier_cls = MagicMock(return_value=identifier)
    identifier_cls.find_one = AsyncMock(return_value=None)

    with patch.object(services, "UserIdentifier", identifier_cls):
        result = await services.activate_user(_kyc(), user)

    assert result == "saved-user"
    assert user.is_active is True
    assert set(user.roles) == {"user"}
    identifier.save.assert_awaited_once()
    assert identifier_cls.call_args.kwargs["type"] == AuthIdentifier.NATIONAL_ID
    assert identifier_cls.call_args.kwargs["verified_at"].tzinfo is not None


@pytest.mark.asyncio
async def test_activate_user_reuses_existing_identifier() -> None:
    """An existing national identifier is not inserted again."""
    user = SimpleNamespace(
        uid="user-1",
        tenant_id="tenant-1",
        roles=[],
        name=None,
        is_active=False,
        save=AsyncMock(return_value="saved-user"),
    )
    identifier_cls = MagicMock()
    identifier_cls.find_one = AsyncMock(return_value=object())
    with patch.object(services, "UserIdentifier", identifier_cls):
        await services.activate_user(_kyc(), user)
    identifier_cls.assert_not_called()


@pytest.mark.asyncio
async def test_activate_user_sets_name_from_civil_data() -> None:
    """Civil registry first/last name populate the user display name."""
    user = SimpleNamespace(
        uid="user-1",
        tenant_id="tenant-1",
        roles=[],
        name=None,
        is_active=False,
        save=AsyncMock(side_effect=lambda: user),
    )
    kyc = _kyc()
    kyc.civil_data = {"data": {"firstName": "Ada", "lastName": "Lovelace"}}
    identifier_cls = MagicMock()
    identifier_cls.find_one = AsyncMock(return_value=object())

    with (
        patch.object(services, "UserIdentifier", identifier_cls),
        patch(
            "apps.identity.user.services.upsert_admin_profile",
            new=AsyncMock(),
        ) as upsert_profile,
    ):
        await services.activate_user(kyc, user)

    assert user.name == "Ada Lovelace"
    upsert_profile.assert_awaited_once()


@pytest.mark.asyncio
async def test_resolve_user_for_national_code_attaches_phone_to_existing() -> None:
    """When national ID belongs to another user, attach phone and return them."""
    current = SimpleNamespace(uid="new-user", tenant_id="tenant-1")
    existing = SimpleNamespace(uid="old-user", tenant_id="tenant-1")
    national_row = SimpleNamespace(user_id="old-user")

    with (
        patch.object(
            services.UserIdentifier,
            "find_one",
            new=AsyncMock(return_value=national_row),
        ),
        patch.object(services.User, "get_item", new=AsyncMock(return_value=existing)),
        patch.object(services, "attach_phone_to_user", new=AsyncMock()) as attach,
        patch.object(
            services, "retire_orphaned_merge_source", new=AsyncMock()
        ) as retire,
    ):
        result = await services.resolve_user_for_national_code(
            current_user=current,
            national_code="0012345678",
            phone="09120000000",
        )

    assert result is existing
    attach.assert_awaited_once_with(
        tenant_id="tenant-1",
        target_user_id="old-user",
        phone="09120000000",
        source_user_id="new-user",
    )
    retire.assert_awaited_once_with(source_user=current)


@pytest.mark.asyncio
async def test_retire_orphaned_merge_source_soft_deletes_empty_shell() -> None:
    """Empty post-merge shells are deactivated and soft-deleted."""
    source = SimpleNamespace(
        uid="new-user",
        tenant_id="tenant-1",
        is_active=True,
        save=AsyncMock(),
    )
    with (
        patch.object(
            services.UserIdentifier, "find_one", new=AsyncMock(return_value=None)
        ),
        patch.object(services.User, "delete_item", new=AsyncMock()) as delete_item,
    ):
        await services.retire_orphaned_merge_source(source_user=source)

    assert source.is_active is False
    source.save.assert_awaited_once()
    delete_item.assert_awaited_once_with(source)


@pytest.mark.asyncio
async def test_retire_orphaned_merge_source_keeps_user_with_identifiers() -> None:
    """Do not delete a source user that still owns another identifier."""
    source = SimpleNamespace(
        uid="new-user",
        tenant_id="tenant-1",
        is_active=True,
        save=AsyncMock(),
    )
    with (
        patch.object(
            services.UserIdentifier,
            "find_one",
            new=AsyncMock(return_value=object()),
        ),
        patch.object(services.User, "delete_item", new=AsyncMock()) as delete_item,
    ):
        await services.retire_orphaned_merge_source(source_user=source)

    assert source.is_active is True
    source.save.assert_not_awaited()
    delete_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_attach_phone_soft_deletes_source_dup() -> None:
    """Duplicate phone on target: remove the source row instead of early-return."""
    source_phone = SimpleNamespace(
        user_id="new-user", is_deleted=False, save=AsyncMock()
    )
    target_phone = object()
    find_one = AsyncMock(side_effect=[target_phone, source_phone])

    with patch.object(services.UserIdentifier, "find_one", new=find_one):
        await services.attach_phone_to_user(
            tenant_id="tenant-1",
            target_user_id="old-user",
            phone="09120000000",
            source_user_id="new-user",
        )

    assert source_phone.is_deleted is True
    source_phone.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_civil_rethrows_http_errors() -> None:
    """Provider BadRequest must not be rewritten as service unavailable."""
    from server.exceptions import BadRequestError

    with (
        patch.object(
            services,
            "get_kyc_provider",
            return_value=SimpleNamespace(
                verify_civil=AsyncMock(
                    side_effect=BadRequestError(error_code="national_birth_mismatch")
                )
            ),
        ),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.verify_civil("001", "13700101")
    assert exc.value.error_code == "national_birth_mismatch"


@pytest.mark.asyncio
async def test_authenticate_user_builds_completed_response() -> None:
    """Successful KYC authentication passes request metadata to token creation."""
    request = MagicMock()
    request.headers.get.return_value = "pytest-agent"
    request.client.host = "127.0.0.1"
    request.url = MagicMock(hostname="sso.test")
    user = SimpleNamespace(uid="user-1", tenant_id="tenant-1")
    payload = SimpleNamespace(amr=["phone_otp"])
    tenant = MagicMock()
    payloads = {TokenType.ACCESS: SimpleNamespace(token="access")}
    response = MagicMock()

    with (
        patch.object(
            services, "create_token_response", new=AsyncMock(return_value=payloads)
        ) as create_tokens,
        patch.object(services, "build_kyc_response", return_value=response) as build,
    ):
        result = await services.authenticate_user(
            _kyc(), request, user, payload, tenant
        )

    assert result is response
    assert create_tokens.await_args.kwargs["user_agent"] == "pytest-agent"
    assert create_tokens.await_args.kwargs["ip"] == "127.0.0.1"
    assert (
        create_tokens.await_args.kwargs["login_flow_result"].status
        == LoginStatus.COMPLETED
    )
    assert build.call_args.kwargs["payloads"] == payloads


@pytest.mark.parametrize("cookie_preferred", [False, True])
def test_build_kyc_response_selects_body_tokens_or_cookies(
    cookie_preferred: bool,
) -> None:
    """Non-cookie clients receive tokens; cookie clients receive auth cookies."""
    request = MagicMock()
    request.url.hostname = "sso.test"
    tenant = MagicMock()
    tenant.config.cookie_header_config.header_or_cookie = "cookie"
    payloads = {
        TokenType.ACCESS: SimpleNamespace(token="access-token"),
        TokenType.REFRESH: SimpleNamespace(token="refresh-token"),
    }

    with (
        patch.object(
            services, "is_cookie_auth_preferred", return_value=cookie_preferred
        ) as preferred,
        patch.object(services, "attach_auth_cookies_to_response") as attach,
    ):
        response = services.build_kyc_response(
            kyc=_kyc(),
            request=request,
            tenant=tenant,
            payloads=payloads,
            status=LoginStatus.COMPLETED,
            domain=None,
        )

    body = json.loads(response.body)
    assert body["status"] == LoginStatus.COMPLETED
    assert ("tokens" in body) is (not cookie_preferred)
    assert preferred.call_count == 2
    if cookie_preferred:
        attach.assert_called_once()
        assert attach.call_args.kwargs["domain"] == "sso.test"
    else:
        attach.assert_not_called()


@pytest.mark.asyncio
async def test_get_user_phone_found_and_missing() -> None:
    """Phone lookup returns the identifier value or None."""
    payload = SimpleNamespace(tenant_id="tenant-1", user_id="user-1")
    with patch.object(
        services.UserIdentifier,
        "find_one",
        new=AsyncMock(return_value=SimpleNamespace(identifier="09120000000")),
    ):
        assert await services.get_user_phone(payload) == "09120000000"

    with patch.object(
        services.UserIdentifier, "find_one", new=AsyncMock(return_value=None)
    ):
        assert await services.get_user_phone(payload) is None
