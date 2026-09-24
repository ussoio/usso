"""
User service functions.

This module provides service functions for user management including
user creation, authentication, credential management, and user lookup.
"""

import asyncio
from datetime import date, datetime

from fastapi_mongo_base.utils import timezone
from fastapi_mongo_base.utils.mongo_aggregate import aggregate_to_list
from usso import UserData, authorization
from usso.utils import validators
from usso_jwt import JWT, JWTConfig

from apps.access_control.role.models import Role
from apps.identity.kyc.models import KYC
from apps.identity.kyc.schemas import KYCStatus
from apps.tenant.models import Tenant
from server.exceptions import BadRequestError, ForbiddenError, UnauthorizedError
from utils.hasher import PasswordHasherService

from ..auth.schemas import (
    AuthIdentifier,
    AuthSecret,
    Identifier,
    LoginRequest,
    Secret,
)
from .models import Credential, User, UserIdentifier


async def assert_assignable_tenant_roles(
    *,
    tenant_id: str,
    user_data: UserData,
    role_names: list[str] | None,
) -> None:
    """
    Ensure each tenant-wide role exists and the caller can grant it.

    ``manage`` on users is enough; assigning a role only requires covering
    that role's scopes (same subset rule as workspace member roles).
    """
    names = [name for name in (role_names or []) if name]
    if not names:
        return

    inviter_scopes = list(user_data.scopes or [])
    for role_name in names:
        role = await Role.find_one({
            "tenant_id": tenant_id,
            "workspace_id": None,
            "name": role_name,
            "is_active": True,
            "is_deleted": False,
        })
        if role is None:
            raise BadRequestError(
                error_code="invalid_role",
                detail=f"Unknown tenant role: {role_name}",
                message={
                    "en": f"Unknown tenant role: {role_name}.",
                    "fa": f"نقش «{role_name}» معتبر نیست.",
                },
            )
        for scope in role.scopes or []:
            if not authorization.has_subset_scope(
                subset_scope=scope, user_scopes=inviter_scopes
            ):
                raise ForbiddenError(
                    error_code="role_scope_insufficient",
                    detail=(
                        f"You cannot assign role '{role_name}' "
                        f"because you lack scope: {scope}"
                    ),
                    message={
                        "en": (
                            f"You cannot assign role '{role_name}' "
                            "with scopes you do not have."
                        ),
                        "fa": (
                            f"نمی‌توانید نقش «{role_name}» را بدهید "
                            "چون همهٔ دسترسی‌های آن را ندارید."
                        ),
                    },
                )


async def upsert_admin_profile(
    *,
    user: User,
    first_name: str | None = None,
    last_name: str | None = None,
) -> None:
    """Persist administrator-provided identity fields on the user profile."""
    updates = {
        key: value
        for key, value in {
            "first_name": first_name,
            "last_name": last_name,
        }.items()
        if value is not None
    }
    if not updates:
        return

    from apps.identity.profile.models import Profile

    profile = await Profile.get_by_user_id(tenant_id=user.tenant_id, user_id=user.uid)
    current = profile.profile_data
    if hasattr(current, "model_copy"):
        profile.profile_data = current.model_copy(update=updates)
    else:
        if hasattr(current, "model_dump"):
            for key, value in current.model_dump().items():
                if not hasattr(current, key):
                    setattr(current, key, value)
        for key, value in updates.items():
            setattr(current, key, value)
        profile.profile_data = current
    await profile.save()


async def upsert_admin_kyc(*, user: User, birth_date: date | None) -> None:
    """Persist administrator-provided birth date in the user's KYC record."""
    if birth_date is None:
        return
    national = await UserIdentifier.find_one({
        "user_id": user.uid,
        "tenant_id": user.tenant_id,
        "type": "national_id",
        "is_deleted": False,
    })
    if national is None:
        return
    kyc = await KYC.find_one({
        "user_id": user.uid,
        "tenant_id": user.tenant_id,
        "is_deleted": False,
    })
    if kyc is None:
        await KYC(
            tenant_id=user.tenant_id,
            user_id=user.uid,
            national_code=national.identifier,
            birth_date=birth_date,
            status=KYCStatus.APPROVED,
        ).save()
    else:
        kyc.national_code = national.identifier
        kyc.birth_date = birth_date
        kyc.status = KYCStatus.APPROVED
        await kyc.save()


def validate_totp(*, secret: str, code: str) -> bool:
    """
    Validate a TOTP code against a secret.

    Args:
        secret: TOTP secret key.
        code: TOTP code to validate.

    Returns:
        True if code is valid, False otherwise.

    """
    import pyotp

    totp = pyotp.TOTP(secret)
    return totp.verify(code)


async def find_user(
    *,
    identifier: Identifier,
    tenant_id: str,
    tenant: Tenant | None = None,
) -> User | None:
    """
    Find a user by identifier within a tenant.

    Args:
        identifier: Identifier object containing type and value.
        tenant_id: Tenant ID to search within.
        tenant: Tenant already resolved for the request, if available.

    Returns:
        User instance if found, None otherwise.

    """
    query = {
        "tenant_id": tenant_id,
        "identifier": identifier.identifier,
        "is_active": True,
        "is_deleted": False,
    }
    if identifier.type:
        query["type"] = identifier.type

    pipeline = [
        {"$match": query},
        {
            "$lookup": {
                "from": "User",
                "localField": "user_id",
                "foreignField": "uid",
                "as": "user",
            }
        },
        {"$unwind": "$user"},
        {
            "$lookup": {
                "from": "Credential",
                "localField": "user_id",
                "foreignField": "user_id",
                "as": "credentials",
            }
        },
        {
            "$project": {
                "identifier": "$$ROOT",
            }
        },
    ]
    if tenant is None:
        pipeline[2:2] = [
            {
                "$lookup": {
                    "from": "Tenant",
                    "localField": "tenant_id",
                    "foreignField": "uid",
                    "as": "tenant",
                }
            },
            {"$unwind": "$tenant"},
        ]

    result = await aggregate_to_list(UserIdentifier, pipeline, length=1)
    if not result:
        return None

    identifier: dict = result[0].get("identifier", {})
    user_identifier = UserIdentifier(**identifier)
    user = User(**identifier.get("user"))
    user.tenant = tenant or Tenant(**identifier.get("tenant"))
    user.current_identifier = user_identifier
    user.credentials = [
        Credential(**credential) for credential in identifier.get("credentials", [])
    ]
    return user


def _verify_password_like(*, credential: Credential, secret: Secret) -> bool:
    """Verify password or OTP credentials with the password hasher."""
    return PasswordHasherService().verify_password(
        hashed=credential.secret, password=secret.secret
    )


def _verify_oauth_credential(*, credential: Credential, secret: Secret) -> bool:
    """Verify an OAuth JWT credential against the expected identifier."""
    jwt = JWT(
        token=secret.secret,
        config=JWTConfig(jwks_url=credential.secret),
    )
    res = jwt.verify()
    email = jwt.payload["email"]
    _, _, canonical_email = validators.validate_email(email)
    return bool(res and canonical_email == getattr(secret, "identifier", None))


def _verify_magic_link_credential(
    *, credential: Credential, secret: Secret, **kwargs: object
) -> bool:
    """Verify a magic-link JWT using JWKS or PEM from kwargs."""
    del credential
    config_kwargs: dict[str, object] = {"maximum_age": kwargs.get("maximum_age")}
    if kwargs.get("jwks_url"):
        config_kwargs["jwks_url"] = kwargs.get("jwks_url")
    else:
        config_kwargs["key"] = kwargs.get("pem")
    jwt = JWT(
        token=secret.secret,
        config=JWTConfig(**config_kwargs),
    )
    return bool(jwt.verify())


def _verify_webauthn_credential(
    *, credential: Credential, secret: Secret, **kwargs: object
) -> bool:
    """Verify a WebAuthn authentication response."""
    import webauthn

    from utils import texttools

    return bool(
        webauthn.verify_authentication_response(
            credential=credential.secret,
            expected_challenge=kwargs.get("challenge"),
            expected_rp_id=kwargs.get("rp_id"),
            expected_origin=kwargs.get("origin"),
            credential_public_key=texttools.base64url_decode(secret.secret),
            credential_current_sign_count=0,  # Start at 0, library will track
        )
    )


def verify_credential(
    *, credential: Credential, secret: Secret, **kwargs: object
) -> bool:
    """
    Verify a credential against a secret.

    Args:
        credential: The credential to verify.
        secret: The secret to verify against.
        **kwargs: Additional keyword arguments.

    Returns:
        True if credential matches secret, False otherwise.

    """
    try:
        if credential.method == AuthSecret.PASSWORD:
            return _verify_password_like(credential=credential, secret=secret)
        if credential.method in {AuthSecret.PHONE_OTP, AuthSecret.EMAIL_OTP}:
            return _verify_password_like(credential=credential, secret=secret)
        if credential.method == AuthSecret.TOTP:
            return validate_totp(secret=credential.secret, code=secret.secret)
        if credential.method == AuthSecret.OAUTH:
            return _verify_oauth_credential(credential=credential, secret=secret)
        if credential.method == AuthSecret.MAGIC_LINK:
            return _verify_magic_link_credential(
                credential=credential, secret=secret, **kwargs
            )
        if credential.method == AuthSecret.TELEGRAM_TOKEN:
            return bool(kwargs.get("telegram_verified"))
        if credential.method == AuthSecret.WEBAUTHN:
            return _verify_webauthn_credential(
                credential=credential, secret=secret, **kwargs
            )
    except Exception:
        return False
    else:
        return credential.secret == secret.secret


async def authenticate_user(*, user: User, secret: Secret, **kwargs: object) -> bool:
    """
    Authenticate a user with a secret.

    Args:
        user: User to authenticate.
        secret: Secret to verify.
        **kwargs: Additional keyword arguments.

    Returns:
        True if authentication succeeds, False otherwise.

    """
    if secret.method == AuthSecret.MAGIC_LINK:
        verify_secret = kwargs.get("jwks_url") or kwargs.get("pem")
        credentials = [
            Credential(
                tenant_id=user.tenant_id,
                user_id=user.uid,
                method=secret.method,
                secret=verify_secret,
            )
        ]
    elif secret.method == AuthSecret.TELEGRAM_TOKEN:
        if not kwargs.get("telegram_verified"):
            return False
        credentials = [
            Credential(
                tenant_id=user.tenant_id,
                user_id=user.uid,
                method=secret.method,
                secret=secret.secret,
            )
        ]
    else:
        credentials = await user.get_credentials(secret.method)

    for credential in credentials:
        is_authenticated = await asyncio.to_thread(
            verify_credential,
            credential=credential,
            secret=secret,
            **kwargs,
        )
        if not is_authenticated:
            continue
        credential.last_used_at = datetime.now(timezone.tz)
        await credential.save()
        return True
    return False


async def add_credential(*, user: User, secret: Secret) -> User:
    """
    Add a credential to a user.

    Args:
        user: User to add credential to.
        secret: Secret containing credential data.

    Returns:
        Updated user instance.

    """
    if not (getattr(secret, "method", None) and getattr(secret, "secret", None)):
        return user

    for credential in await user.get_credentials(secret.method):
        if credential.secret == secret.secret:
            return user

    credential_secret = secret.secret
    if secret.method == AuthSecret.PASSWORD:
        credential_secret = await asyncio.to_thread(
            PasswordHasherService().hash_password,
            secret.secret,
        )

    credential = Credential(
        tenant_id=user.tenant_id,
        user_id=user.uid,
        method=secret.method,
        secret=credential_secret,
        is_active=True,
    )
    await credential.save()
    user.credentials.append(credential)
    return user


async def create_user(*, login: LoginRequest, tenant: Tenant, **kwargs: object) -> User:
    """
    Create a new user with login credentials.

    Args:
        login: Login request containing identifier and secret.
        tenant: Tenant to create user in.
        **kwargs: Additional keyword arguments (e.g., name, is_active).

    Returns:
        Created User instance.

    Raises:
        DuplicateKeyError: If the identifier is already taken in this tenant.

    """
    from pymongo.errors import DuplicateKeyError

    existing = await UserIdentifier.find_one({
        "tenant_id": tenant.uid,
        "type": login.type,
        "identifier": login.identifier,
        "is_deleted": False,
    })
    if existing is not None:
        raise DuplicateKeyError(
            f"Identifier already exists: {login.type}={login.identifier}",
            11000,
            {
                "keyPattern": {
                    "tenant_id": 1,
                    "type": 1,
                    "identifier": 1,
                },
                "keyValue": {
                    "tenant_id": tenant.uid,
                    "type": login.type,
                    "identifier": login.identifier,
                },
            },
        )

    user = User(
        tenant_id=tenant.uid,
        **kwargs,
    )
    user.current_identifier = UserIdentifier(
        tenant_id=tenant.uid,
        type=login.type,
        identifier=login.identifier,
        user_id=user.uid,
    )
    await user.save()
    await asyncio.gather(
        user.current_identifier.save(),
        add_credential(user=user, secret=login),
    )
    user.tenant = tenant

    if tenant.config.workspace.enabled:
        from apps.access_control.workspace.services import ensure_personal_workspace

        await ensure_personal_workspace(user=user)

    return user


def needs_verification(
    *,
    identifier: Identifier,
    method: AuthSecret | None = None,
    tenant: Tenant | None = None,
) -> bool:
    """Determine if the login method requires verification (e.g., email, phone)."""
    from apps.tenant.config import ApprovalMode

    if identifier.type == AuthIdentifier.EMAIL:
        if tenant and tenant.config.registration.approval_mode == ApprovalMode.NONE:
            return False
        return method != AuthSecret.MAGIC_LINK

    if identifier.type == AuthIdentifier.PHONE:
        return True

    if method == AuthSecret.TOTP:
        return True

    return method == AuthSecret.WEBAUTHN


async def find_or_create_user(
    *,
    login_request: LoginRequest,
    tenant: Tenant,
) -> tuple[User, bool]:
    """
    Find existing user or create a new one.

    Args:
        login_request: Login request containing identifier and secret.
        tenant: Tenant to search/create user in.
        **kwargs: Additional keyword arguments for user creation.

    Returns:
        User instance (existing or newly created).

    """
    user = await find_user(
        identifier=login_request,
        tenant_id=tenant.uid,
        tenant=tenant,
    )
    if user:
        return user, False

    if not tenant.config.registration.is_allowed:
        raise UnauthorizedError(
            error_code="registration_closed",
            detail="Registration is closed",
            message={
                "en": "Registration is closed",
                "fa": "ثبت‌نام در حال حاضر امکان‌پذیر نیست.",
            },
        )

    user = await create_user(login=login_request, tenant=tenant)
    return user, True


def _workspace_display_name(workspace: object | None) -> str | None:
    """Prefer the workspace name, then organization code — never a raw uid."""
    if workspace is None:
        return None
    name = str(getattr(workspace, "name", None) or "").strip()
    if name:
        return name
    code = str(getattr(workspace, "organization_code", None) or "").strip()
    return code or None


async def attach_user_list_directory(
    items: list[object],
    *,
    tenant_id: str,
) -> None:
    """Fill identifiers and workspace names on a user list page."""
    if not items:
        return

    from apps.access_control.workspace.models import Workspace

    from .schemas import UserIdentifierSchema, UserWorkspaceRef

    user_ids = [item.uid for item in items]
    identifiers = await UserIdentifier.get_query(
        tenant_id=tenant_id,
        user_id_in=user_ids,
    ).to_list()
    identifiers_by_user: dict[str, list] = {}
    for identifier in identifiers:
        identifiers_by_user.setdefault(identifier.user_id, []).append(identifier)

    workspace_ids = {
        workspace_id
        for item in items
        for workspace_id in (item.workspace_ids or [])
        if workspace_id != item.uid
    }
    workspaces_by_id: dict[str, object] = {}
    if workspace_ids:
        workspaces = await Workspace.get_query(
            tenant_id=tenant_id,
            uid__in=list(workspace_ids),
        ).to_list()
        workspaces_by_id = {workspace.uid: workspace for workspace in workspaces}

    for item in items:
        if not item.identifiers:
            item.identifiers = [
                UserIdentifierSchema.model_validate(identifier)
                for identifier in identifiers_by_user.get(item.uid, [])
            ]
        item.workspaces = [
            UserWorkspaceRef(
                uid=workspace_id,
                name=_workspace_display_name(workspaces_by_id.get(workspace_id)),
                organization_code=getattr(
                    workspaces_by_id.get(workspace_id), "organization_code", None
                ),
                type=getattr(workspaces_by_id.get(workspace_id), "type", None),
            )
            for workspace_id in (item.workspace_ids or [])
            if workspace_id != item.uid
        ]
