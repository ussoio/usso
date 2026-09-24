"""Focused unit coverage for identity user services."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pymongo.errors import DuplicateKeyError

from apps.identity.auth.enums import AuthIdentifier, AuthSecret
from apps.identity.auth.schemas import LoginRequest
from apps.identity.user import services
from apps.tenant.config import ApprovalMode
from server.exceptions import BadRequestError, ForbiddenError, UnauthorizedError


def _secret(method: AuthSecret, value: str = "value") -> SimpleNamespace:
    return SimpleNamespace(method=method, secret=value, identifier="a@example.com")


def _user(**kwargs: object) -> SimpleNamespace:
    values = {
        "uid": "user-1",
        "tenant_id": "tenant-1",
        "credentials": [],
        "get_credentials": AsyncMock(return_value=[]),
        "save": AsyncMock(),
    }
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_validate_totp_delegates_to_pyotp() -> None:
    with patch("pyotp.TOTP") as totp_cls:
        totp_cls.return_value.verify.return_value = True
        assert services.validate_totp(secret="base32", code="123456") is True
    totp_cls.assert_called_once_with("base32")
    assert totp_cls.return_value.verify.call_args.args == ("123456",)


def test_validate_totp_rejects_invalid_code() -> None:
    with patch("pyotp.TOTP") as totp_cls:
        totp_cls.return_value.verify.return_value = False
        assert not services.validate_totp(secret="base32", code="bad")


@pytest.mark.asyncio
async def test_find_user_handles_missing_and_hydrates_relations() -> None:
    tenant = SimpleNamespace(uid="tenant-1")
    with patch.object(services, "aggregate_to_list", new=AsyncMock(return_value=[])):
        assert (
            await services.find_user(
                identifier=SimpleNamespace(type=None, identifier="alice"),
                tenant_id="tenant-1",
                tenant=tenant,
            )
            is None
        )

    document = {
        "identifier": {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "type": AuthIdentifier.EMAIL,
            "identifier": "a@example.com",
            "user": {"uid": "user-1", "tenant_id": "tenant-1", "roles": []},
            "credentials": [
                {
                    "tenant_id": "tenant-1",
                    "user_id": "user-1",
                    "method": AuthSecret.PASSWORD,
                    "secret": "hashed",
                }
            ],
        }
    }
    identifier_model = SimpleNamespace(identifier="a@example.com")
    credential_model = SimpleNamespace(method=AuthSecret.PASSWORD)
    user_model = _user()
    with (
        patch.object(
            services, "aggregate_to_list", new=AsyncMock(return_value=[document])
        ) as aggregate,
        patch.object(
            services, "UserIdentifier", MagicMock(return_value=identifier_model)
        ),
        patch.object(services, "Credential", MagicMock(return_value=credential_model)),
        patch.object(services, "User", MagicMock(return_value=user_model)),
    ):
        user = await services.find_user(
            identifier=SimpleNamespace(
                type=AuthIdentifier.EMAIL, identifier="a@example.com"
            ),
            tenant_id="tenant-1",
            tenant=tenant,
        )

    assert user.uid == "user-1"
    assert user.tenant is tenant
    assert user.current_identifier.identifier == "a@example.com"
    assert user.credentials[0].method == AuthSecret.PASSWORD
    assert aggregate.await_args.args[1][0]["$match"]["type"] == AuthIdentifier.EMAIL


@pytest.mark.asyncio
async def test_find_user_hydrates_tenant_from_aggregation() -> None:
    document = {
        "identifier": {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "type": AuthIdentifier.USERNAME,
            "identifier": "alice",
            "user": {"uid": "user-1", "tenant_id": "tenant-1"},
            "tenant": {"uid": "tenant-1"},
            "credentials": [],
        }
    }
    user_model = _user()
    tenant_model = SimpleNamespace(uid="tenant-1")
    with (
        patch.object(
            services, "aggregate_to_list", new=AsyncMock(return_value=[document])
        ) as aggregate,
        patch.object(services, "UserIdentifier", MagicMock()),
        patch.object(services, "User", MagicMock(return_value=user_model)),
        patch.object(services, "Tenant", MagicMock(return_value=tenant_model)),
    ):
        user = await services.find_user(
            identifier=SimpleNamespace(
                type=AuthIdentifier.USERNAME, identifier="alice"
            ),
            tenant_id="tenant-1",
        )

    assert user.tenant is tenant_model
    pipeline = aggregate.await_args.args[1]
    assert pipeline[2]["$lookup"]["from"] == "Tenant"

    with patch.object(
        services, "aggregate_to_list", new=AsyncMock(return_value=[])
    ) as aggregate:
        assert (
            await services.find_user(
                identifier=SimpleNamespace(type=None, identifier="alice"),
                tenant_id="tenant-1",
            )
            is None
        )
    assert any(
        stage.get("$lookup", {}).get("from") == "Tenant"
        for stage in aggregate.await_args.args[1]
    )


@pytest.mark.parametrize(
    ("method", "expected"),
    [
        (AuthSecret.TELEGRAM_TOKEN, True),
    ],
)
def test_verify_credential_simple_methods(method: AuthSecret, expected: bool) -> None:
    credential = SimpleNamespace(method=method, secret="value")
    kwargs = {"telegram_verified": True} if method == AuthSecret.TELEGRAM_TOKEN else {}
    assert (
        services.verify_credential(
            credential=credential, secret=_secret(method), **kwargs
        )
        is expected
    )


def test_verify_credential_hashed_otp() -> None:
    with patch.object(services, "PasswordHasherService") as hasher:
        hasher.return_value.verify_password.return_value = True
        assert services.verify_credential(
            credential=SimpleNamespace(
                method=AuthSecret.PHONE_OTP, secret="hashed-otp"
            ),
            secret=_secret(AuthSecret.PHONE_OTP, "123456"),
        )
        hasher.return_value.verify_password.assert_called_once_with(
            hashed="hashed-otp",
            password="123456",
        )


def test_verify_credential_rejects_plaintext_otp_storage() -> None:
    assert not services.verify_credential(
        credential=SimpleNamespace(method=AuthSecret.EMAIL_OTP, secret="123456"),
        secret=_secret(AuthSecret.EMAIL_OTP, "123456"),
    )


def test_verify_credential_password_totp_oauth_and_magic_link() -> None:
    with patch.object(services, "PasswordHasherService") as hasher:
        hasher.return_value.verify_password.return_value = True
        assert services.verify_credential(
            credential=SimpleNamespace(method=AuthSecret.PASSWORD, secret="hash"),
            secret=_secret(AuthSecret.PASSWORD, "plain"),
        )

    with patch.object(services, "validate_totp", return_value=True) as validate:
        assert services.verify_credential(
            credential=SimpleNamespace(
                method=AuthSecret.TOTP,
                secret="totp-secret",
                last_used_at=None,
            ),
            secret=_secret(AuthSecret.TOTP, "123456"),
        )
    validate.assert_called_once_with(
        secret="totp-secret",
        code="123456",
    )


@pytest.mark.asyncio
async def test_authenticate_user_records_credential_use() -> None:
    credential = SimpleNamespace(
        uid="totp-1",
        method=AuthSecret.TOTP,
        last_used_at=None,
        save=AsyncMock(),
    )
    user = _user(get_credentials=AsyncMock(return_value=[credential]))
    with patch.object(services.asyncio, "to_thread", new=AsyncMock(return_value=True)):
        assert await services.authenticate_user(
            user=user,
            secret=_secret(AuthSecret.TOTP, "123456"),
        )
    assert credential.last_used_at is not None
    credential.save.assert_awaited_once()


def test_verify_credential_oauth_and_magic_link_paths() -> None:
    jwt = MagicMock()
    jwt.verify.return_value = True
    jwt.payload = {"email": "a@example.com"}
    assert not services.verify_credential(
        credential=SimpleNamespace(method=AuthSecret.OAUTH, secret="https://jwks"),
        secret=_secret(AuthSecret.OAUTH, "jwt"),
    )
    with (
        patch.object(services, "JWT", return_value=jwt),
        patch.object(
            services.validators,
            "validate_email",
            return_value=(True, None, "a@example.com"),
        ),
    ):
        assert services.verify_credential(
            credential=SimpleNamespace(method=AuthSecret.OAUTH, secret="https://jwks"),
            secret=_secret(AuthSecret.OAUTH, "jwt"),
            oauth_verified=True,
        )

    with patch.object(services, "JWT", return_value=jwt) as jwt_cls:
        assert services.verify_credential(
            credential=SimpleNamespace(method=AuthSecret.MAGIC_LINK, secret="unused"),
            secret=_secret(AuthSecret.MAGIC_LINK, "jwt"),
            pem="public-key",
            maximum_age=60,
            magic_link_verified=True,
        )
    assert jwt_cls.call_args.kwargs["config"].key == {
        "kty": "oct",
        "k": "cHVibGljLWtleQ",
    }

    with patch.object(services, "JWT", return_value=jwt) as jwt_cls:
        assert services.verify_credential(
            credential=SimpleNamespace(method=AuthSecret.MAGIC_LINK, secret="unused"),
            secret=_secret(AuthSecret.MAGIC_LINK, "jwt"),
            jwks_url="https://issuer.test/jwks.json",
            maximum_age=60,
            magic_link_verified=True,
        )
    assert (
        jwt_cls.call_args.kwargs["config"].jwks_url == "https://issuer.test/jwks.json"
    )


def test_verify_credential_webauthn() -> None:
    with (
        patch("webauthn.verify_authentication_response", return_value=True) as verify,
        patch("utils.texttools.base64url_decode", return_value=b"public-key"),
    ):
        assert services.verify_credential(
            credential=SimpleNamespace(method=AuthSecret.WEBAUTHN, secret="assertion"),
            secret=_secret(AuthSecret.WEBAUTHN, "cHVi"),
            challenge="challenge",
            rp_id="app.test",
            origin="https://app.test",
        )
    assert verify.call_args.kwargs["credential_public_key"] == b"public-key"


def test_verify_credential_returns_false_on_verifier_error() -> None:
    with patch.object(
        services, "PasswordHasherService", side_effect=RuntimeError("bad")
    ):
        assert (
            services.verify_credential(
                credential=SimpleNamespace(method=AuthSecret.PASSWORD, secret="hash"),
                secret=_secret(AuthSecret.PASSWORD),
            )
            is False
        )


@pytest.mark.asyncio
async def test_authenticate_user_success_and_telegram_rejection() -> None:
    credential = SimpleNamespace(
        method=AuthSecret.PASSWORD, last_used_at=None, save=AsyncMock()
    )
    user = _user(get_credentials=AsyncMock(return_value=[credential]))
    with patch.object(
        services.asyncio, "to_thread", new=AsyncMock(return_value=True)
    ) as to_thread:
        assert (
            await services.authenticate_user(
                user=user, secret=_secret(AuthSecret.PASSWORD, "plain")
            )
            is True
        )
    assert credential.last_used_at.tzinfo is not None
    credential.save.assert_awaited_once()
    assert to_thread.await_args.kwargs["credential"] is credential

    assert (
        await services.authenticate_user(
            user=user,
            secret=_secret(AuthSecret.TELEGRAM_TOKEN, "token"),
            telegram_verified=False,
        )
        is False
    )


@pytest.mark.asyncio
async def test_authenticate_user_skips_failed_credential_and_telegram_succeeds() -> (
    None
):
    first = SimpleNamespace(
        method=AuthSecret.PASSWORD, last_used_at=None, save=AsyncMock()
    )
    second = SimpleNamespace(
        method=AuthSecret.PASSWORD, last_used_at=None, save=AsyncMock()
    )
    user = _user(get_credentials=AsyncMock(return_value=[first, second]))
    with patch.object(
        services.asyncio,
        "to_thread",
        new=AsyncMock(side_effect=[False, True]),
    ):
        assert (
            await services.authenticate_user(
                user=user, secret=_secret(AuthSecret.PASSWORD, "plain")
            )
            is True
        )
    first.save.assert_not_awaited()
    second.save.assert_awaited_once()

    with (
        patch.object(
            services,
            "Credential",
            MagicMock(
                return_value=SimpleNamespace(
                    method=AuthSecret.TELEGRAM_TOKEN,
                    last_used_at=None,
                    save=AsyncMock(),
                )
            ),
        ),
        patch.object(services.asyncio, "to_thread", new=AsyncMock(return_value=True)),
    ):
        assert (
            await services.authenticate_user(
                user=user,
                secret=_secret(AuthSecret.TELEGRAM_TOKEN, "token"),
                telegram_verified=True,
            )
            is True
        )

    with patch.object(services.asyncio, "to_thread", new=AsyncMock(return_value=False)):
        assert (
            await services.authenticate_user(
                user=_user(get_credentials=AsyncMock(return_value=[first])),
                secret=_secret(AuthSecret.PASSWORD, "wrong"),
            )
            is False
        )


@pytest.mark.asyncio
async def test_authenticate_magic_link_builds_ephemeral_credential() -> None:
    user = _user()
    credential = SimpleNamespace(
        method=AuthSecret.MAGIC_LINK,
        secret="https://jwks",
        save=AsyncMock(),
    )
    with (
        patch.object(services, "Credential", MagicMock(return_value=credential)),
        patch.object(
            services.asyncio, "to_thread", new=AsyncMock(return_value=True)
        ) as to_thread,
    ):
        assert (
            await services.authenticate_user(
                user=user,
                secret=_secret(AuthSecret.MAGIC_LINK, "token"),
                jwks_url="https://jwks",
            )
            is True
        )
    assert to_thread.await_args.kwargs["credential"].secret == "https://jwks"


@pytest.mark.asyncio
async def test_authenticate_telegram_builds_credential_and_handles_failure() -> None:
    user = _user()
    credential = SimpleNamespace(secret="token", save=AsyncMock())
    with (
        patch.object(services, "Credential", MagicMock(return_value=credential)),
        patch.object(services.asyncio, "to_thread", new=AsyncMock(return_value=False)),
    ):
        assert (
            await services.authenticate_user(
                user=user,
                secret=_secret(AuthSecret.TELEGRAM_TOKEN, "token"),
                telegram_verified=True,
            )
            is False
        )
    credential.save.assert_not_awaited()


@pytest.mark.asyncio
async def test_add_credential_skips_invalid_duplicate_and_hashes_password() -> None:
    user = _user()
    assert (
        await services.add_credential(
            user=user, secret=SimpleNamespace(method=None, secret=None)
        )
        is user
    )

    existing = SimpleNamespace(secret="same")
    user.get_credentials = AsyncMock(return_value=[existing])
    assert (
        await services.add_credential(
            user=user, secret=_secret(AuthSecret.TOTP, "same")
        )
        is user
    )

    user.get_credentials = AsyncMock(return_value=[])
    created = SimpleNamespace(save=AsyncMock())
    credential_cls = MagicMock(return_value=created)
    with (
        patch.object(services, "Credential", credential_cls),
        patch.object(
            services.asyncio, "to_thread", new=AsyncMock(return_value="hashed")
        ),
    ):
        assert (
            await services.add_credential(
                user=user, secret=_secret(AuthSecret.PASSWORD, "plain")
            )
            is user
        )
    assert credential_cls.call_args.kwargs["secret"] == "hashed"
    assert created in user.credentials
    created.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_user_rejects_duplicate_identifier() -> None:
    login = LoginRequest(
        type=AuthIdentifier.EMAIL,
        identifier="a@example.com",
        method=AuthSecret.PASSWORD,
        secret="pw",
    )
    tenant = SimpleNamespace(uid="tenant-1")
    with (
        patch.object(
            services.UserIdentifier, "find_one", new=AsyncMock(return_value=object())
        ),
        pytest.raises(DuplicateKeyError),
    ):
        await services.create_user(login=login, tenant=tenant)


@pytest.mark.asyncio
async def test_create_user_saves_relations_and_personal_workspace() -> None:
    login = LoginRequest(
        type=AuthIdentifier.EMAIL,
        identifier="a@example.com",
        method=AuthSecret.PASSWORD,
        secret="pw",
    )
    tenant = SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(workspace=SimpleNamespace(enabled=True)),
    )
    user = _user()
    identifier = SimpleNamespace(save=AsyncMock())
    user_cls = MagicMock(return_value=user)
    identifier_cls = MagicMock(return_value=identifier)
    identifier_cls.find_one = AsyncMock(return_value=None)
    with (
        patch.object(services, "User", user_cls),
        patch.object(services, "UserIdentifier", identifier_cls),
        patch.object(
            services, "add_credential", new=AsyncMock(return_value=user)
        ) as add_credential,
        patch(
            "apps.access_control.workspace.services.ensure_personal_workspace",
            new=AsyncMock(),
        ) as ensure_workspace,
    ):
        assert (
            await services.create_user(login=login, tenant=tenant, name="Alice") is user
        )
    user.save.assert_awaited_once()
    identifier.save.assert_awaited_once()
    add_credential.assert_awaited_once_with(user=user, secret=login)
    ensure_workspace.assert_awaited_once_with(user=user)
    assert user.current_identifier is identifier
    assert user.tenant is tenant


@pytest.mark.parametrize(
    ("identifier_type", "method", "approval", "expected"),
    [
        (AuthIdentifier.EMAIL, AuthSecret.PASSWORD, ApprovalMode.NONE, False),
        (AuthIdentifier.EMAIL, AuthSecret.PASSWORD, ApprovalMode.IDENTIFIER, True),
        (AuthIdentifier.EMAIL, AuthSecret.MAGIC_LINK, ApprovalMode.IDENTIFIER, False),
        (AuthIdentifier.PHONE, AuthSecret.PASSWORD, ApprovalMode.NONE, True),
        (AuthIdentifier.USERNAME, AuthSecret.TOTP, ApprovalMode.NONE, True),
        (AuthIdentifier.USERNAME, AuthSecret.WEBAUTHN, ApprovalMode.NONE, True),
        (AuthIdentifier.USERNAME, AuthSecret.PASSWORD, ApprovalMode.NONE, False),
    ],
)
def test_needs_verification_branches(
    identifier_type: AuthIdentifier,
    method: AuthSecret,
    approval: ApprovalMode,
    expected: bool,
) -> None:
    tenant = SimpleNamespace(
        config=SimpleNamespace(registration=SimpleNamespace(approval_mode=approval))
    )
    assert (
        services.needs_verification(
            identifier=SimpleNamespace(type=identifier_type),
            method=method,
            tenant=tenant,
        )
        is expected
    )


@pytest.mark.asyncio
async def test_find_or_create_user_existing_closed_and_created() -> None:
    login = MagicMock()
    tenant = SimpleNamespace(
        uid="tenant-1",
        config=SimpleNamespace(registration=SimpleNamespace(is_allowed=True)),
    )
    existing = object()
    with patch.object(services, "find_user", new=AsyncMock(return_value=existing)):
        assert await services.find_or_create_user(
            login_request=login, tenant=tenant
        ) == (existing, False)

    tenant.config.registration.is_allowed = False
    with (
        patch.object(services, "find_user", new=AsyncMock(return_value=None)),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await services.find_or_create_user(login_request=login, tenant=tenant)
    assert exc.value.error_code == "registration_closed"

    tenant.config.registration.is_allowed = True
    created = object()
    with (
        patch.object(services, "find_user", new=AsyncMock(return_value=None)),
        patch.object(services, "create_user", new=AsyncMock(return_value=created)),
    ):
        assert await services.find_or_create_user(
            login_request=login, tenant=tenant
        ) == (created, True)


@pytest.mark.asyncio
async def test_attach_user_list_directory_fills_names_and_identifiers() -> None:
    """User list chips resolve workspace names instead of falling back to uids."""
    item = SimpleNamespace(
        uid="user-1",
        identifiers=[],
        workspace_ids=["user-1", "ws-1", "ws-missing"],
        workspaces=None,
    )
    identifier = SimpleNamespace(user_id="user-1", type="phone", identifier="98912")
    workspace = SimpleNamespace(
        uid="ws-1", name="  شرکت نمونه  ", organization_code="103", type="business"
    )
    ident_query = SimpleNamespace(to_list=AsyncMock(return_value=[identifier]))
    ws_query = SimpleNamespace(to_list=AsyncMock(return_value=[workspace]))
    with (
        patch.object(services.UserIdentifier, "get_query", return_value=ident_query),
        patch(
            "apps.access_control.workspace.models.Workspace.get_query",
            return_value=ws_query,
        ),
        patch(
            "apps.identity.user.schemas.UserIdentifierSchema.model_validate",
            side_effect=lambda value: value,
        ),
    ):
        await services.attach_user_list_directory([item], tenant_id="tenant-1")
    assert item.identifiers[0].identifier == "98912"
    assert [ref.uid for ref in item.workspaces] == ["ws-1", "ws-missing"]
    assert item.workspaces[0].name == "شرکت نمونه"
    assert item.workspaces[1].name is None


@pytest.mark.asyncio
async def test_upsert_admin_profile_skips_when_no_fields() -> None:
    user = _user()
    with patch(
        "apps.identity.profile.models.Profile.get_by_user_id", new=AsyncMock()
    ) as get_profile:
        await services.upsert_admin_profile(user=user)
    get_profile.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_admin_profile_merges_identity_fields() -> None:
    user = _user()
    current = SimpleNamespace(
        model_dump=MagicMock(return_value={"first_name": "Ada", "avatar_url": "a.png"})
    )
    profile = SimpleNamespace(profile_data=current, save=AsyncMock())
    with patch(
        "apps.identity.profile.models.Profile.get_by_user_id",
        new=AsyncMock(return_value=profile),
    ) as get_profile:
        await services.upsert_admin_profile(
            user=user,
            last_name="Lovelace",
        )
    get_profile.assert_awaited_once_with(tenant_id="tenant-1", user_id="user-1")
    assert profile.profile_data.first_name == "Ada"
    assert profile.profile_data.last_name == "Lovelace"
    profile.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_upsert_admin_kyc_skips_without_birth_date_or_national_id() -> None:
    user = _user()
    with patch.object(services.UserIdentifier, "find_one", new=AsyncMock()) as find_id:
        await services.upsert_admin_kyc(user=user, birth_date=None)
        find_id.assert_not_awaited()

    with (
        patch.object(
            services.UserIdentifier, "find_one", new=AsyncMock(return_value=None)
        ) as find_id,
        patch.object(services.KYC, "find_one", new=AsyncMock()) as find_kyc,
    ):
        from datetime import date

        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    find_id.assert_awaited_once()
    find_kyc.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_admin_kyc_creates_or_updates_record() -> None:
    from datetime import date

    user = _user()
    national = SimpleNamespace(identifier="0012345678")
    existing = SimpleNamespace(
        national_code="old",
        birth_date=None,
        status=None,
        save=AsyncMock(),
    )
    with (
        patch.object(
            services.UserIdentifier,
            "find_one",
            new=AsyncMock(return_value=national),
        ),
        patch.object(
            services.KYC, "find_one", new=AsyncMock(return_value=existing)
        ),
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    assert existing.birth_date == date(2001, 8, 29)
    assert existing.national_code == "0012345678"
    existing.save.assert_awaited_once()

    created = SimpleNamespace(save=AsyncMock())
    kyc_cls = MagicMock(return_value=created)
    kyc_cls.find_one = AsyncMock(return_value=None)
    with (
        patch.object(
            services.UserIdentifier,
            "find_one",
            new=AsyncMock(return_value=national),
        ),
        patch.object(services, "KYC", kyc_cls),
    ):
        await services.upsert_admin_kyc(user=user, birth_date=date(2001, 8, 29))
    kyc_cls.assert_called_once()
    created.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_assert_assignable_tenant_roles_skips_empty() -> None:
    with patch.object(services.Role, "find_one", new=AsyncMock()) as find_one:
        await services.assert_assignable_tenant_roles(
            tenant_id="t1",
            user_data=SimpleNamespace(scopes=["manage:sso/usso/user"]),
            role_names=[],
        )
    find_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_assert_assignable_tenant_roles_rejects_unknown() -> None:
    with (
        patch.object(services.Role, "find_one", new=AsyncMock(return_value=None)),
        pytest.raises(BadRequestError) as exc,
    ):
        await services.assert_assignable_tenant_roles(
            tenant_id="t1",
            user_data=SimpleNamespace(scopes=["*:*"]),
            role_names=["cds-admin"],
        )
    assert exc.value.error_code == "invalid_role"


@pytest.mark.asyncio
async def test_assert_assignable_tenant_roles_rejects_uncovered_scopes() -> None:
    role = SimpleNamespace(name="admin", scopes=["*:*"])
    with (
        patch.object(services.Role, "find_one", new=AsyncMock(return_value=role)),
        pytest.raises(ForbiddenError) as exc,
    ):
        await services.assert_assignable_tenant_roles(
            tenant_id="t1",
            user_data=SimpleNamespace(scopes=["manage:sso/usso/user"]),
            role_names=["admin"],
        )
    assert exc.value.error_code == "role_scope_insufficient"


@pytest.mark.asyncio
async def test_assert_assignable_tenant_roles_allows_covered_role() -> None:
    role = SimpleNamespace(
        name="cds-admin",
        scopes=["manage:sso/usso/user", "manage:sso/usso/workspace"],
    )
    with patch.object(
        services.Role, "find_one", new=AsyncMock(return_value=role)
    ) as find_one:
        await services.assert_assignable_tenant_roles(
            tenant_id="t1",
            user_data=SimpleNamespace(
                scopes=["manage:sso/usso/user", "manage:sso/usso/workspace"]
            ),
            role_names=["cds-admin"],
        )
    find_one.assert_awaited_once()
