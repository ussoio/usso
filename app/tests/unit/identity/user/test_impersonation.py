"""Impersonation modes, readonly scopes, and OTP consent."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from usso.user import TokenType

from apps.identity.session.schemas import SessionType
from apps.identity.user.impersonation import (
    _mask_identifier,
    apply_impersonation_mode_to_scopes,
    build_impersonation_claims,
    create_impersonation_session,
    create_impersonation_tokens,
    merge_impersonation_claims_for_workspace,
    to_readonly_scopes,
)
from apps.identity.user.jwt_claims import jwt_claims_for_user
from apps.identity.user.models import User
from apps.identity.user.schemas import ImpersonationMode


def test_to_readonly_scopes_downgrades_elevated_and_star() -> None:
    """Elevated actions and * become read; existing read scopes stay."""
    scopes = [
        "read:sso/usso/user",
        "manage:finance/exchange/order?workspace_id=w1",
        "*:*",
        "create:accounting/wallet",
        "read:sso/usso/user",  # duplicate
    ]
    assert to_readonly_scopes(scopes) == [
        "read:sso/usso/user",
        "read:finance/exchange/order?workspace_id=w1",
        "read:*",
        "read:accounting/wallet",
    ]


def test_mask_identifier_hides_prefix() -> None:
    """Short values are fully masked; longer values keep last 4 chars."""
    assert _mask_identifier("ab") == "**"
    assert _mask_identifier("1234") == "****"
    assert _mask_identifier("09123456789") == "*******6789"


def test_apply_mode_full_keeps_scopes() -> None:
    """Full mode does not rewrite scopes."""
    scopes = ["manage:x", "read:y"]
    assert (
        apply_impersonation_mode_to_scopes(scopes, mode=ImpersonationMode.FULL)
        == scopes
    )


def test_jwt_claims_for_user_snapshots_display_name() -> None:
    """Access-token claims carry the user's name at issue time."""
    user = MagicMock(spec=User)
    user.custom_claims = {"dept": "fx"}
    user.name = "علی رضایی"
    assert jwt_claims_for_user(user) == {
        "dept": "fx",
        "name": "علی رضایی",
        "user_name": "علی رضایی",
    }


def test_build_impersonation_claims() -> None:
    """Claims always carry admin id, mode, and consent."""
    user = MagicMock(spec=User)
    user.custom_claims = {"k": "v"}
    claims = build_impersonation_claims(
        user=user,
        impersonated_by="admin-1",
        mode=ImpersonationMode.READONLY,
        consent="otp",
    )
    assert claims == {
        "k": "v",
        "impersonated_by": "admin-1",
        "impersonation_mode": "readonly",
        "impersonation_consent": "otp",
    }


def test_merge_impersonation_claims_for_workspace() -> None:
    """Workspace switch keeps impersonation audit claims."""
    user = MagicMock(spec=User)
    user.custom_claims = {"name": "x"}
    previous = MagicMock()
    previous.claims = {
        "impersonated_by": "admin-1",
        "impersonation_mode": "readonly",
        "impersonation_consent": "admin",
    }
    claims, session_type, mode = merge_impersonation_claims_for_workspace(
        user=user, previous_session=previous
    )
    assert session_type == SessionType.IMPERSONATION
    assert mode == "readonly"
    assert claims["impersonated_by"] == "admin-1"
    assert claims["name"] == "x"


@pytest.mark.asyncio
async def test_impersonation_session_readonly_filters_scopes() -> None:
    """Readonly mode filters scopes before session save."""
    user = MagicMock(spec=User)
    user.uid = "target-user"
    user.tenant_id = "tenant-1"
    user.custom_claims = {}

    tenant = MagicMock()
    tenant.uid = "tenant-1"
    tenant.config.token.get_timeout.return_value = 60
    tenant.config.token.refresh_timeout = 2_592_000
    tenant.config.workspace.enabled = True

    with (
        patch(
            "utils.net.get_location",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "apps.identity.auth.services.token._resolve_login_workspace_id",
            new_callable=AsyncMock,
            return_value="target-user",
        ),
        patch(
            "apps.identity.auth.services.token._resolve_token_roles_scopes",
            new_callable=AsyncMock,
            return_value=(["member"], ["manage:finance/x", "read:sso/y"]),
        ),
        patch(
            "apps.identity.user.impersonation.AuthSession",
        ) as session_cls,
    ):
        session_instance = MagicMock()
        session_cls.return_value = session_instance
        session_instance.save = AsyncMock()

        await create_impersonation_session(
            user=user,
            tenant=tenant,
            impersonated_by="admin-1",
            mode=ImpersonationMode.READONLY,
            consent="admin",
            user_agent="test",
            ip="127.0.0.1",
        )

    kwargs = session_cls.call_args.kwargs
    assert kwargs["scopes"] == ["read:finance/x", "read:sso/y"]
    assert kwargs["amr"] == ["impersonation", "impersonation_readonly"]
    assert kwargs["claims"]["impersonation_mode"] == "readonly"
    assert kwargs["meta_data"]["impersonation_consent"] == "admin"
    session_instance.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_impersonation_otp_consumes_matching_credential() -> None:
    """OTP verify accepts matching purpose/admin/mode and deactivates credential."""
    from apps.identity.user.impersonation import verify_impersonation_otp

    user = MagicMock(spec=User)
    user.uid = "target"
    user.tenant_id = "t1"
    tenant = MagicMock()
    tenant.uid = "t1"

    cred = MagicMock()
    cred.uid = "credential-1"
    cred.secret = "$argon2id$stored-hash"
    cred.expires_at = None
    cred.meta_data = {
        "purpose": "impersonation",
        "requested_by": "admin-1",
        "impersonation_mode": "full",
    }
    cred.save = AsyncMock()

    query = MagicMock()
    query.to_list = AsyncMock(return_value=[cred])
    collection = MagicMock()
    collection.update_one = AsyncMock(return_value=SimpleNamespace(modified_count=1))

    with (
        patch(
            "apps.identity.user.impersonation.Credential.get_query",
            return_value=query,
        ),
        patch(
            "apps.identity.user.impersonation.Credential.get_pymongo_collection",
            return_value=collection,
        ),
        patch(
            "apps.identity.user.impersonation.PasswordHasherService.verify_password",
            return_value=True,
        ),
    ):
        await verify_impersonation_otp(
            user=user,
            tenant=tenant,
            requested_by="admin-1",
            mode=ImpersonationMode.FULL,
            otp="123456",
        )

    assert cred.is_active is False
    collection.update_one.assert_awaited_once()


def test_impersonation_access_token_uses_session_roles_and_claims() -> None:
    """Access JWT payload must come from the session, not stale user.roles."""
    user = MagicMock(spec=User)
    user.uid = "target-user"
    user.tenant_id = "tenant-1"
    user.roles = ["stale-global"]

    tenant = MagicMock()
    tenant.primary_url = "https://example.test"
    tenant.config.token.get_timeout.return_value = 3600
    tenant.sign_jwt.side_effect = lambda payload, **_: payload

    session = MagicMock()
    session.uid = "session-1"
    session.workspace_id = "ws-1"
    session.roles = ["resolved-role"]
    session.scopes = ["read:x"]
    session.amr = ["impersonation", "impersonation_readonly"]
    session.claims = {
        "impersonated_by": "admin-1",
        "impersonation_mode": "readonly",
        "impersonation_consent": "admin",
    }

    payloads = create_impersonation_tokens(
        user=user,
        tenant=tenant,
        session=session,
    )

    access = payloads[TokenType.ACCESS]
    assert access.roles == ["resolved-role"]
    assert access.scopes == ["read:x"]
    assert access.claims["impersonated_by"] == "admin-1"
    assert access.claims["impersonation_mode"] == "readonly"
    assert access.workspace_id == "ws-1"
    assert "impersonation_readonly" in access.amr


@pytest.mark.asyncio
async def test_pick_otp_identifier_prefers_phone() -> None:
    """Without an explicit type, phone is preferred over email."""
    from apps.identity.auth.enums import AuthIdentifier
    from apps.identity.user.impersonation import _pick_otp_identifier

    phone = MagicMock(
        type=AuthIdentifier.PHONE,
        identifier="09120000000",
        is_active=True,
        is_deleted=False,
    )
    email = MagicMock(
        type=AuthIdentifier.EMAIL,
        identifier="u@example.test",
        is_active=True,
        is_deleted=False,
    )
    user = MagicMock(spec=User)
    user.get_identifiers = AsyncMock(return_value=[email, phone])
    result = await _pick_otp_identifier(user=user, identifier_type=None)
    assert result is phone


@pytest.mark.asyncio
async def test_pick_otp_identifier_explicit_type_missing() -> None:
    """Requested identifier type missing raises BadRequestError."""
    from apps.identity.auth.enums import AuthIdentifier
    from apps.identity.user.impersonation import _pick_otp_identifier
    from server.exceptions import BadRequestError

    email = MagicMock(
        type=AuthIdentifier.EMAIL,
        identifier="u@example.test",
        is_active=True,
        is_deleted=False,
    )
    user = MagicMock(spec=User)
    user.get_identifiers = AsyncMock(return_value=[email])
    with pytest.raises(BadRequestError) as exc:
        await _pick_otp_identifier(user=user, identifier_type=AuthIdentifier.PHONE)
    assert exc.value.error_code == "identifier_not_found"


@pytest.mark.asyncio
async def test_pick_otp_identifier_no_destination() -> None:
    """No phone/email identifiers raise no_otp_destination."""
    from apps.identity.user.impersonation import _pick_otp_identifier
    from server.exceptions import BadRequestError

    user = MagicMock(spec=User)
    user.get_identifiers = AsyncMock(return_value=[])
    with pytest.raises(BadRequestError) as exc:
        await _pick_otp_identifier(user=user, identifier_type=None)
    assert exc.value.error_code == "no_otp_destination"


@pytest.mark.asyncio
async def test_send_impersonation_otp_success() -> None:
    """send_impersonation_otp stores credential and sends message."""
    from apps.identity.auth.enums import AuthIdentifier
    from apps.identity.user.impersonation import send_impersonation_otp
    from apps.tenant.messaging.enums import MessageChannelType

    user = MagicMock(spec=User)
    user.uid = "target"
    user.tenant_id = "t1"
    phone = MagicMock(
        type=AuthIdentifier.PHONE,
        identifier="09120000000",
        is_active=True,
        is_deleted=False,
    )
    phone.type = AuthIdentifier.PHONE
    user.get_identifiers = AsyncMock(return_value=[phone])

    tenant = MagicMock()
    tenant.uid = "t1"
    tenant.primary_domain = "sso.example.test"
    tenant.config.auth.otp_length = 6
    tenant.config.auth.otp_timeout = 300
    tenant.secrets.channel_configs = {
        "sms": object(),
        "bale": object(),
        "email": object(),
    }

    channel = MagicMock()
    channel.channel_type = MessageChannelType.SMS

    query = MagicMock()
    query.to_list = AsyncMock(return_value=[])

    credential = MagicMock()
    credential.save = AsyncMock()
    cred_cls = MagicMock(return_value=credential)
    cred_cls.get_query = MagicMock(return_value=query)

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=MessageChannelType.SMS,
        ),
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.create_channel",
            return_value=channel,
        ),
        patch(
            "apps.identity.user.impersonation.Credential",
            cred_cls,
        ),
        patch(
            "apps.identity.user.impersonation._generate_random_otp",
            return_value=123456,
            create=True,
        ),
        patch(
            "apps.identity.auth.services.message._generate_random_otp",
            return_value=123456,
        ),
        patch(
            "apps.tenant.messaging.services.asend",
            new=AsyncMock(),
        ) as asend,
    ):
        result = await send_impersonation_otp(
            user=user,
            tenant=tenant,
            requested_by="admin-1",
            mode=ImpersonationMode.FULL,
        )

    assert result["status"] == "otp_sent"
    assert result["identifier_type"] == AuthIdentifier.PHONE.value
    credential.save.assert_awaited_once()
    asend.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_impersonation_otp_too_many_pending() -> None:
    """More than three pending impersonation OTPs are rate-limited."""
    from apps.identity.auth.enums import AuthIdentifier
    from apps.identity.user.impersonation import (
        IMPERSONATION_OTP_PURPOSE,
        send_impersonation_otp,
    )
    from apps.tenant.messaging.enums import MessageChannelType
    from server.exceptions import TooManyRequestsError

    user = MagicMock(spec=User)
    user.uid = "target"
    phone = MagicMock(
        type=AuthIdentifier.PHONE,
        identifier="09120000000",
        is_active=True,
        is_deleted=False,
    )
    user.get_identifiers = AsyncMock(return_value=[phone])

    tenant = MagicMock()
    tenant.uid = "t1"
    tenant.config.auth.otp_length = 6
    tenant.config.auth.otp_timeout = 300
    tenant.secrets.channel_configs = {
        "sms": object(),
        "bale": object(),
        "email": object(),
    }

    channel = MagicMock()
    channel.channel_type = MessageChannelType.SMS

    pending = [
        MagicMock(meta_data={"purpose": IMPERSONATION_OTP_PURPOSE}) for _ in range(4)
    ]
    query = MagicMock()
    query.to_list = AsyncMock(return_value=pending)
    cred_cls = MagicMock()
    cred_cls.get_query = MagicMock(return_value=query)

    with (
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.resolve_channel_type",
            return_value=MessageChannelType.SMS,
        ),
        patch(
            "apps.tenant.messaging.channels.base.AbstractChannel.create_channel",
            return_value=channel,
        ),
        patch("apps.identity.user.impersonation.Credential", cred_cls),
        pytest.raises(TooManyRequestsError),
    ):
        await send_impersonation_otp(
            user=user,
            tenant=tenant,
            requested_by="admin-1",
            mode=ImpersonationMode.READONLY,
        )


@pytest.mark.asyncio
async def test_verify_impersonation_otp_rejects_mismatch() -> None:
    """OTP verify rejects wrong purpose/admin/mode/code."""
    from apps.identity.user.impersonation import verify_impersonation_otp
    from server.exceptions import UnauthorizedError

    user = MagicMock(spec=User)
    user.uid = "target"
    user.tenant_id = "t1"
    tenant = MagicMock()
    tenant.uid = "t1"

    cred = MagicMock()
    cred.secret = "999999"
    cred.expires_at = None
    cred.meta_data = {
        "purpose": "impersonation",
        "requested_by": "other-admin",
        "impersonation_mode": "full",
    }
    query = MagicMock()
    query.to_list = AsyncMock(return_value=[cred])

    with (
        patch(
            "apps.identity.user.impersonation.Credential.get_query",
            return_value=query,
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await verify_impersonation_otp(
            user=user,
            tenant=tenant,
            requested_by="admin-1",
            mode=ImpersonationMode.FULL,
            otp="123456",
        )
    assert exc.value.error_code == "invalid_otp"


@pytest.mark.asyncio
async def test_verify_impersonation_otp_skips_wrong_mode_and_expired() -> None:
    """Candidates with the wrong mode or an expired naive timestamp are ignored."""
    from datetime import datetime, timedelta

    from fastapi_mongo_base.utils import timezone

    from apps.identity.user.impersonation import verify_impersonation_otp
    from server.exceptions import UnauthorizedError

    # Naive timestamps are interpreted as timezone.tz (UTC); build them from UTC.
    expired_naive = (datetime.now(timezone.tz) - timedelta(minutes=1)).replace(
        tzinfo=None
    )
    wrong_mode = MagicMock(
        secret="not-hashed",
        meta_data={
            "purpose": "impersonation",
            "requested_by": "admin",
            "impersonation_mode": "readonly",
        },
        expires_at=None,
    )
    expired = MagicMock(
        secret="not-hashed",
        meta_data={
            "purpose": "impersonation",
            "requested_by": "admin",
            "impersonation_mode": "full",
        },
        expires_at=expired_naive,
    )
    query = MagicMock(to_list=AsyncMock(return_value=[wrong_mode, expired]))
    with (
        patch(
            "apps.identity.user.impersonation.Credential.get_query",
            return_value=query,
        ),
        pytest.raises(UnauthorizedError),
    ):
        await verify_impersonation_otp(
            user=SimpleNamespace(uid="user"),
            tenant=SimpleNamespace(uid="tenant"),
            requested_by="admin",
            mode=ImpersonationMode.FULL,
            otp="123456",
        )


@pytest.mark.asyncio
async def test_consume_impersonation_otp_rejects_concurrent_replay() -> None:
    """Only the request that atomically changes the credential may succeed."""
    from datetime import datetime

    from apps.identity.user.impersonation import _consume_impersonation_otp
    from server.exceptions import UnauthorizedError

    collection = MagicMock(
        update_one=AsyncMock(return_value=SimpleNamespace(modified_count=0))
    )
    with (
        patch(
            "apps.identity.user.impersonation.Credential.get_pymongo_collection",
            return_value=collection,
        ),
        pytest.raises(UnauthorizedError) as replay,
    ):
        await _consume_impersonation_otp(
            match=SimpleNamespace(uid="credential"),
            user=SimpleNamespace(uid="user"),
            tenant=SimpleNamespace(uid="tenant"),
            now=datetime.now(),
        )
    assert replay.value.error_code == "invalid_otp"


def test_build_impersonation_amr_otp_consent() -> None:
    """OTP consent appends impersonation_otp AMR."""
    from apps.identity.user.impersonation import build_impersonation_amr

    amr = build_impersonation_amr(mode=ImpersonationMode.FULL, consent="otp")
    assert amr == ["impersonation", "impersonation_otp"]


def test_merge_impersonation_claims_without_admin() -> None:
    """Non-impersonation sessions keep regular login type."""
    user = MagicMock(spec=User)
    user.custom_claims = {"k": "v"}
    previous = MagicMock()
    previous.claims = {}
    claims, session_type, mode = merge_impersonation_claims_for_workspace(
        user=user, previous_session=previous
    )
    assert session_type == SessionType.REGULAR_LOGIN
    assert mode is None
    assert claims == {"k": "v"}


def test_manage_user_scope_allows_crud_not_impersonation() -> None:
    """User managers (manage) can create users; impersonation requires admin."""
    from usso.authorization import check_access

    path = "sso/usso/user"
    assert (
        check_access(
            user_scopes=["manage:sso/usso/user"],
            resource_path=path,
            action="create",
        )
        is True
    )
    assert (
        check_access(
            user_scopes=["manage:sso/usso/user"],
            resource_path=path,
            action="admin",
        )
        is False
    )
    assert (
        check_access(
            user_scopes=["admin:sso/usso/user"],
            resource_path=path,
            action="admin",
        )
        is True
    )
