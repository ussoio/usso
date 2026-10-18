"""Workspace services."""

import logging
import re
import secrets
from datetime import date, datetime, timedelta

from fastapi_mongo_base.utils import timezone
from usso import UserData, authorization

from apps.access_control.role.models import Role
from apps.access_control.workspace.models import Workspace, WorkspaceInvitation
from apps.access_control.workspace.schemas import (
    DEFAULT_INVITATION_EXPIRES_IN_DAYS,
    InvitationStatus,
    UserSearchResultSchema,
    WorkspaceInvitationCreateSchema,
    WorkspaceMemberIdentitySchema,
    WorkspaceMemberSchema,
    WorkspaceSchema,
)
from apps.identity.auth.enums import AuthIdentifier
from apps.identity.kyc.models import KYC
from apps.identity.user.models import User, UserIdentifier
from apps.tenant.models import Tenant
from server.exceptions import (
    AlreadyExistsError,
    BadRequestError,
    ForbiddenError,
    NotFoundError,
)

from .scopes import get_default_workspace_scopes

logger = logging.getLogger(__name__)

PERSONAL_WORKSPACE_DEFAULT_NAME = "شخصی"
PERSONAL_WORKSPACE_OWNER_ROLE = "owner"
MANAGEMENT_WORKSPACE_DEFAULT_NAME = "management"


async def get_user_national_code(*, user_id: str, tenant_id: str) -> str | None:
    """Return the user's verified personal national code from identifiers."""
    user = await User.get_item(uid=user_id, tenant_id=tenant_id)
    if not user:
        return None

    identifiers = await user.get_identifiers(not_cached=True)
    national_id_identifier = next(
        (i for i in identifiers if i.type == AuthIdentifier.NATIONAL_ID),
        None,
    )
    return national_id_identifier.identifier if national_id_identifier else None


async def _user_birth_date(user_id: str, tenant_id: str) -> date | None:
    kyc = await KYC.get_by_user_id(user_id=user_id, tenant_id=tenant_id)
    return kyc.birth_date if kyc else None


async def assert_assignable_workspace_role(
    *,
    tenant: Tenant,
    user_data: UserData,
    workspace_id: str,
    role_name: str,
) -> Role:
    """
    Ensure the role exists for the workspace and the inviter can grant it.

    The inviter's JWT scopes must cover every scope on the target role
    (subset semantics). Prevents privilege escalation via free-form role names.
    """
    role = await Role.find_one({
        "tenant_id": tenant.uid,
        "workspace_id": workspace_id,
        "name": role_name,
        "is_active": True,
        "is_deleted": False,
    })
    if role is None:
        role = await Role.find_one({
            "tenant_id": tenant.uid,
            "workspace_id": None,
            "name": role_name,
            "is_active": True,
            "is_deleted": False,
        })
    if role is None:
        raise BadRequestError(
            error_code="invalid_workspace_role",
            detail=f"Unknown workspace role: {role_name}",
            message={
                "en": f"Unknown workspace role: {role_name}.",
                "fa": f"نقش فضای کاری «{role_name}» معتبر نیست.",
            },
        )

    inviter_scopes = list(user_data.scopes or [])
    if has_system_workspace_admin(user_scopes=inviter_scopes):
        return role
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
    return role


async def _get_user_national_code(user_data: UserData) -> str:
    user = await User.get_item(uid=user_data.user_id, tenant_id=user_data.tenant_id)
    national_code = (user.custom_claims or {}).get("national_code") if user else None
    if not national_code:
        national_code = await get_user_national_code(
            user_id=user_data.user_id,
            tenant_id=user_data.tenant_id,
        )
    if not national_code:
        raise BadRequestError(
            error_code="national_code_not_found",
            detail="National code not found",
            message={
                "en": "Complete identity verification first.",
                "fa": "اول تأیید هویتتان را کامل کنید.",
            },
        )
    return national_code


async def _add_user_to_workspace(*, user: User, workspace_id: str) -> None:
    if not user.workspace_ids or workspace_id not in user.workspace_ids:
        user.workspace_ids = [*(user.workspace_ids or []), workspace_id]
        await user.save()


async def get_or_create_workspace_with_organization_details(
    organization_code: str,
    tenant_id: str,
    name: str | None = None,
    slug: str | None = None,
) -> Workspace:
    """Find or create a workspace keyed by organization code (no external inquiry)."""
    return await find_or_create_simple_organization_workspace(
        tenant_id=tenant_id,
        organization_code=organization_code,
        name=name,
        slug=slug,
    )


async def find_or_create_workspace(
    *,
    tenant_id: str,
    name: str,
    slug: str | None = None,
) -> Workspace:
    """Create a slug-based workspace; an existing slug is never a join request."""
    if slug:
        existing = await Workspace.find_one({
            "slug": slug,
            "tenant_id": tenant_id,
            "is_deleted": False,
        })
        if existing:
            raise AlreadyExistsError(
                error_code="workspace_slug_exists",
                detail="Workspace slug already exists",
                message={
                    "en": "A workspace already uses this slug.",
                    "fa": "این شناسه قبلاً برای فضای کاری دیگری استفاده شده است.",
                },
            )

    return await Workspace.create_item({
        "tenant_id": tenant_id,
        "name": name,
        "slug": slug or secrets.token_urlsafe(8),
        "is_active": True,
        "meta_data": {"kind": "organization"},
    })


async def find_or_create_simple_organization_workspace(
    *,
    tenant_id: str,
    organization_code: str | None,
    name: str | None = None,
    slug: str | None = None,
) -> Workspace:
    """Find/create an org workspace without external registry inquiry."""
    if organization_code:
        existing = await Workspace.find_one({
            "organization_code": organization_code,
            "tenant_id": tenant_id,
            "is_deleted": False,
        })
        if existing:
            return existing

    return await Workspace.create_item({
        "tenant_id": tenant_id,
        "organization_code": organization_code,
        "name": name or organization_code or "workspace",
        "slug": slug or secrets.token_urlsafe(8),
        "is_active": False,
        "meta_data": {"kind": "organization"},
    })


async def create_workspace_provision(
    *,
    user_data: UserData,
    item: WorkspaceSchema,
) -> Workspace:
    """
    Create an organization workspace in the tenant catalog.

    Intended for unscoped workspace admins (``admin:sso/usso/workspace`` /
    ``*:*``) via ``POST /workspaces``. Does not auto-add the caller as a
    member; use ``POST /workspaces/mine`` (join) or add_workspace_member.
    """
    user = await User.get_item(uid=user_data.user_id, tenant_id=user_data.tenant_id)
    if user is None:
        raise BadRequestError(
            error_code="user_not_found",
            detail="User not found",
            message={
                "en": "User not found.",
                "fa": "کاربر پیدا نشد.",
            },
        )

    organization_code = item.organization_code
    if organization_code:
        existing = await Workspace.find_one({
            "organization_code": organization_code,
            "tenant_id": user_data.tenant_id,
            "is_deleted": False,
        })
        if existing:
            if not existing.is_active:
                existing.is_active = True
                await existing.save()
            return existing
    elif item.slug:
        existing = await Workspace.find_one({
            "slug": item.slug,
            "tenant_id": user_data.tenant_id,
            "is_deleted": False,
        })
        if existing:
            raise AlreadyExistsError(
                error_code="workspace_slug_exists",
                detail="Workspace slug already exists",
            )

    workspace = await Workspace.create_item({
        "tenant_id": user_data.tenant_id,
        "name": item.name,
        "organization_code": organization_code,
        "slug": item.slug or secrets.token_urlsafe(8),
        "is_active": True,
        "meta_data": {"kind": "organization", "created_by_admin": True},
    })
    await _init_workspace_roles(workspace=workspace)
    return workspace


# Backward-compatible alias (prefer create_workspace_provision).
create_workspace_by_admin = create_workspace_provision


async def create_workspace(user_data: UserData, item: WorkspaceSchema) -> Workspace:
    """
    Create or join an organization workspace for the caller.

    Used by ``POST /workspaces/mine`` (and non-elevated ``POST /workspaces``
    for backward compatibility). When
    ``tenant.config.workspace.verification_provider`` is set, that plugin both
    resolves the workspace and verifies the caller. Without a provider, create
    is local-only. Always adds the caller to ``workspace_ids``.
    """
    if item.parent_id:
        return await create_child_workspace(user_data=user_data, item=item)

    organization_code = item.organization_code

    user = await User.get_item(uid=user_data.user_id, tenant_id=user_data.tenant_id)
    if user is None:
        raise BadRequestError(
            error_code="user_not_found",
            detail="User not found",
            message={
                "en": "User not found.",
                "fa": "کاربر پیدا نشد.",
            },
        )

    tenant = await Tenant.get_by_uid(user_data.tenant_id)
    if tenant is None:
        raise BadRequestError(
            error_code="tenant_not_found",
            detail="Tenant not found",
            message={"en": "Tenant not found.", "fa": "مستأجر پیدا نشد."},
        )

    workspace_cfg = getattr(getattr(tenant, "config", None), "workspace", None)
    provider = getattr(workspace_cfg, "verification_provider", None)
    verifier = None
    if provider:
        from apps.access_control.workspace.verification import get_verifier

        verifier = get_verifier(provider)
        workspace = await verifier.ensure_workspace(
            tenant=tenant,
            organization_code=organization_code,
            name=item.name,
            slug=item.slug,
        )
    elif organization_code:
        workspace = await find_or_create_simple_organization_workspace(
            tenant_id=user_data.tenant_id,
            organization_code=organization_code,
            name=item.name,
            slug=item.slug,
        )
    else:
        workspace = await find_or_create_workspace(
            tenant_id=user_data.tenant_id,
            name=item.name,
            slug=item.slug,
        )

    if workspace and user.workspace_ids and workspace.uid in user.workspace_ids:
        return workspace

    if verifier is not None:
        await verifier.verify_create(
            tenant=tenant,
            user_data=user_data,
            user=user,
            workspace=workspace,
            organization_code=organization_code,
        )

    if not getattr(workspace, "is_active", True):
        workspace.is_active = True
        await workspace.save()

    new_role = await _init_workspace_roles(workspace=workspace)
    await _add_user_to_workspace(user=user, workspace_id=workspace.uid)
    user.workspace_roles[workspace.uid] = [new_role.name]
    await user.save()

    return workspace


async def create_child_workspace(
    *,
    user_data: UserData,
    item: WorkspaceSchema,
) -> Workspace:
    """Create a child workspace under an active non-personal parent."""
    parent_id = item.parent_id
    if not parent_id:
        raise BadRequestError(
            error_code="parent_id_required",
            detail="parent_id is required for child workspace creation",
            message={
                "en": "Parent workspace is required.",
                "fa": "فضای کاری پدر لازم است.",
            },
        )

    require_workspace_manage(user_data=user_data, workspace_id=parent_id)
    parent = await require_workspace_active(
        tenant_id=user_data.tenant_id, workspace_id=parent_id
    )
    if parent.is_personal:
        raise BadRequestError(
            error_code="personal_cannot_be_parent",
            detail="Personal workspace cannot be a parent",
            message={
                "en": "Personal workspace cannot have child workspaces.",
                "fa": "فضای کاری شخصی نمی‌تواند فضای فرزند داشته باشد.",
            },
        )

    if item.slug:
        existing = await Workspace.find_one({
            "slug": item.slug,
            "tenant_id": user_data.tenant_id,
            "is_deleted": False,
        })
        if existing:
            raise AlreadyExistsError(
                error_code="workspace_slug_exists",
                detail="Workspace slug already exists",
            )

    user = await User.get_item(uid=user_data.user_id, tenant_id=user_data.tenant_id)
    if user is None:
        raise BadRequestError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )

    workspace = await Workspace.create_item({
        "tenant_id": user_data.tenant_id,
        "name": item.name,
        "slug": item.slug or secrets.token_urlsafe(8),
        "organization_code": item.organization_code,
        "is_active": False,
        "parent_id": parent.uid,
        "ancestor_ids": [*parent.ancestor_ids, parent.uid],
    })
    new_role = await _init_workspace_roles(workspace=workspace)
    await _add_user_to_workspace(user=user, workspace_id=workspace.uid)
    user.workspace_roles = {
        **(user.workspace_roles or {}),
        workspace.uid: [new_role.name],
    }
    await user.save()
    return workspace


async def _ensure_workspace_role(
    *,
    workspace: Workspace,
    name: str,
    description: str,
    scopes: list[str],
) -> Role:
    existing = await Role.find_one({
        "tenant_id": workspace.tenant_id,
        "workspace_id": workspace.uid,
        "name": name,
        "is_deleted": False,
    })
    if existing:
        return existing
    return await Role.create_item({
        "name": name,
        "description": description,
        "scopes": scopes,
        "workspace_id": workspace.uid,
        "tenant_id": workspace.tenant_id,
    })


async def _init_workspace_roles(*, workspace: Workspace) -> Role:
    """Create default workspace-scoped roles after workspace creation."""
    await _ensure_workspace_role(
        workspace=workspace,
        name="member",
        description="Workspace member",
        scopes=get_default_workspace_scopes()["workspace_member_scopes"],
    )
    return await _ensure_workspace_role(
        workspace=workspace,
        name="CEO",
        description="Chief Executive Officer",
        scopes=get_default_workspace_scopes()["workspace_ceo_scopes"],
    )


WORKSPACE_MANAGER_SCOPE = "manage:sso/usso/member?workspace_id={workspace_id}"


async def backfill_workspace_manager_scope() -> int:
    """
    Give existing workspace CEO roles the workspace-scoped member manage scope.

    Roles created before the scope existed are never rewritten by
    ``_ensure_workspace_role``. Idempotent startup step; returns roles updated.
    """
    updated = 0
    roles = await Role.find({
        "name": "CEO",
        "workspace_id": {"$ne": None},
        "is_deleted": False,
    }).to_list()
    for role in roles:
        scope = WORKSPACE_MANAGER_SCOPE.format(workspace_id=role.workspace_id)
        if scope in (role.scopes or []):
            continue
        role.scopes = [*(role.scopes or []), scope]
        await role.save()
        updated += 1
    if updated:
        logger.info("backfill_workspace_manager_scope updated=%s", updated)
    return updated


async def _init_personal_workspace_roles(*, workspace: Workspace) -> Role:
    """Create the default owner role for a personal workspace."""
    existing = await Role.find_one({
        "tenant_id": workspace.tenant_id,
        "workspace_id": workspace.uid,
        "name": PERSONAL_WORKSPACE_OWNER_ROLE,
        "is_deleted": False,
    })
    if existing:
        return existing

    return await Role.create_item({
        "name": PERSONAL_WORKSPACE_OWNER_ROLE,
        "description": "Personal workspace owner",
        "scopes": get_default_workspace_scopes()["personal_workspace_owner_scopes"],
        "workspace_id": workspace.uid,
        "tenant_id": workspace.tenant_id,
    })


async def ensure_personal_workspace(
    *,
    user: User,
    tenant: Tenant | None = None,
) -> Workspace:
    """
    Ensure the user has a personal workspace with uid == user.uid.

    Creates the workspace and owner role if missing, and attaches membership
    on the user document. Idempotent.
    """
    if tenant is None:
        tenant = await Tenant.get_by_uid(user.tenant_id)

    workspace = await Workspace.find_one({
        "uid": user.uid,
        "tenant_id": user.tenant_id,
        "is_deleted": False,
    })
    if workspace is None:
        is_active = bool(
            tenant and tenant.config.workspace.personal_workspace_active_by_default
        )
        workspace = Workspace(
            uid=user.uid,
            tenant_id=user.tenant_id,
            name=PERSONAL_WORKSPACE_DEFAULT_NAME,
            slug=f"personal-{user.uid}",
            is_active=is_active,
            meta_data={"kind": "personal"},
            type="personal",
        )
        await workspace.save()
    elif (
        tenant
        and tenant.config.workspace.personal_workspace_active_by_default
        and not workspace.is_active
    ):
        # Sync existing personal workspaces with the tenant default without
        # forcing inactive when the config is false (manual activations stay).
        workspace.is_active = True
        await workspace.save()

    owner_role = await _init_personal_workspace_roles(workspace=workspace)

    changed = False
    if user.uid not in (user.workspace_ids or []):
        user.workspace_ids = [*(user.workspace_ids or []), user.uid]
        changed = True

    current_roles = list((user.workspace_roles or {}).get(user.uid, []))
    if owner_role.name not in current_roles:
        user.workspace_roles = {
            **(user.workspace_roles or {}),
            user.uid: [*current_roles, owner_role.name],
        }
        changed = True

    if changed:
        await user.save()

    return workspace


async def ensure_management_workspace(
    *,
    tenant: Tenant,
    admin_user: User | None = None,
) -> Workspace | None:
    """
    Ensure the tenant has an org management workspace with uid == tenant.uid.

    Only runs when ``tenant.config.workspace.enabled`` is true. Creates an
    active management workspace if missing, initializes CEO (manage) roles,
    and optionally attaches the founding admin as a member. Idempotent.
    """
    if not tenant.config.workspace.enabled:
        return None

    workspace = await Workspace.find_one({
        "uid": tenant.uid,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if workspace is None:
        workspace = Workspace(
            uid=tenant.uid,
            tenant_id=tenant.uid,
            name=MANAGEMENT_WORKSPACE_DEFAULT_NAME,
            slug=f"management-{tenant.uid}",
            is_active=True,
            meta_data={"kind": "management"},
        )
        await workspace.save()

    manager_role = await _init_workspace_roles(workspace=workspace)

    if admin_user is None:
        return workspace

    changed = False
    if tenant.uid not in (admin_user.workspace_ids or []):
        admin_user.workspace_ids = [*(admin_user.workspace_ids or []), tenant.uid]
        changed = True

    current_roles = list((admin_user.workspace_roles or {}).get(tenant.uid, []))
    if manager_role.name not in current_roles:
        admin_user.workspace_roles = {
            **(admin_user.workspace_roles or {}),
            tenant.uid: [*current_roles, manager_role.name],
        }
        changed = True

    if changed:
        await admin_user.save()

    return workspace


async def list_active_descendant_ids(
    *,
    tenant_id: str,
    workspace_id: str,
) -> list[str]:
    """Return uids of active descendants of workspace_id (any depth)."""
    workspaces = await Workspace.find({
        "tenant_id": tenant_id,
        "ancestor_ids": workspace_id,
        "is_active": True,
        "is_deleted": False,
    }).to_list()
    return [w.uid for w in workspaces]


async def list_membered_active_descendant_ids(
    *,
    user: User,
    workspace_id: str,
) -> list[str]:
    """Active descendants of workspace_id that the user is also a member of."""
    member_ids = set(user.workspace_ids or [])
    if not member_ids:
        return []
    descendants = await list_active_descendant_ids(
        tenant_id=user.tenant_id, workspace_id=workspace_id
    )
    return [d for d in descendants if d in member_ids]


async def list_workspace_members(
    *,
    workspace_id: str,
    tenant_id: str,
    offset: int,
    limit: int,
) -> tuple[list[WorkspaceMemberSchema], int]:
    """List users in a workspace with their workspace-scoped roles."""
    users, total = await User.list_total_combined(
        tenant_id=tenant_id,
        offset=offset,
        limit=limit,
        workspace_ids=workspace_id,
    )
    items = [
        WorkspaceMemberSchema(
            uid=user.uid,
            name=user.name,
            birth_date=await _user_birth_date(user.uid, tenant_id),
            identifiers=list(getattr(user, "identifiers", [])),
            roles=list((user.workspace_roles or {}).get(workspace_id, [])),
            is_active=user.is_active,
            avatar_url=user.avatar_url,
        )
        for user in users
    ]
    return items, total


async def get_workspace_member_identity(
    *,
    workspace_id: str,
    user_id: str,
    tenant_id: str,
) -> WorkspaceMemberIdentitySchema:
    """Return one member's user identity and workspace context."""
    workspace = await Workspace.get_item(uid=workspace_id, tenant_id=tenant_id)
    if workspace is None or not workspace.is_active:
        raise NotFoundError(
            error_code="workspace_not_found",
            detail="Workspace not found or inactive",
            message={"en": "Workspace not found.", "fa": "فضای کاری پیدا نشد."},
        )
    user = await User.get_item(uid=user_id, tenant_id=tenant_id)
    if user is None or workspace_id not in (user.workspace_ids or []):
        raise NotFoundError(
            error_code="workspace_member_not_found",
            detail="User is not a member of this workspace",
            message={
                "en": "Workspace member not found.",
                "fa": "عضو موردنظر در این فضای کاری پیدا نشد.",
            },
        )
    identifiers = await user.get_identifiers()
    member = WorkspaceMemberSchema(
        uid=user.uid,
        name=user.name,
        birth_date=await _user_birth_date(user.uid, tenant_id),
        identifiers=identifiers,
        roles=list((user.workspace_roles or {}).get(workspace_id, [])),
        is_active=user.is_active,
        avatar_url=user.avatar_url,
    )
    return WorkspaceMemberIdentitySchema(
        user_id=user.uid,
        workspace_id=workspace.uid,
        user=member,
        workspace=WorkspaceSchema.model_validate(workspace),
        role=member.roles[0] if member.roles else None,
    )


async def add_workspace_member(
    *,
    tenant: Tenant,
    user_data: UserData,
    workspace_id: str,
    target_user_id: str,
    role: str,
) -> WorkspaceMemberSchema:
    """Add a user to a workspace without invitation (manage:sso/usso/member)."""
    require_workspace_enabled(tenant)
    if not can_manage_workspace_members(user_data=user_data, workspace_id=workspace_id):
        raise ForbiddenError(
            error_code="user_manage_denied",
            detail="You do not have manage access on workspace members",
            message={
                "en": "You do not have access to manage workspace members.",
                "fa": "دسترسی ندارید.",
            },
        )
    workspace = await require_workspace_active(
        tenant_id=tenant.uid, workspace_id=workspace_id
    )
    # Backfill default roles for workspaces created before member role existed.
    await _init_workspace_roles(workspace=workspace)

    user = await User.get_item(uid=target_user_id, tenant_id=tenant.uid)
    if user is None:
        raise NotFoundError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )

    await assert_assignable_workspace_role(
        tenant=tenant,
        user_data=user_data,
        workspace_id=workspace_id,
        role_name=role,
    )

    await _add_user_to_workspace(user=user, workspace_id=workspace_id)
    roles = list((user.workspace_roles or {}).get(workspace_id, []))
    if role not in roles:
        user.workspace_roles = {
            **(user.workspace_roles or {}),
            workspace_id: [*roles, role],
        }
        await user.save()

    return WorkspaceMemberSchema(
        uid=user.uid,
        name=user.name,
        birth_date=await _user_birth_date(user.uid, tenant.uid),
        identifiers=await user.get_identifiers(),
        roles=list((user.workspace_roles or {}).get(workspace_id, [])),
        is_active=user.is_active,
        avatar_url=user.avatar_url,
    )


async def remove_workspace_member(
    *,
    tenant: Tenant,
    user_data: UserData,
    workspace_id: str,
    target_user_id: str,
) -> None:
    """Remove a user from a workspace (manage:sso/usso/member)."""
    require_workspace_enabled(tenant)
    if not can_manage_workspace_members(user_data=user_data, workspace_id=workspace_id):
        raise ForbiddenError(
            error_code="user_manage_denied",
            detail="You do not have manage access on workspace members",
            message={
                "en": "You do not have access to manage workspace members.",
                "fa": "دسترسی ندارید.",
            },
        )

    user = await User.get_item(uid=target_user_id, tenant_id=tenant.uid)
    if user is None:
        raise NotFoundError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )

    if workspace_id in (user.workspace_ids or []):
        user.workspace_ids = [w for w in user.workspace_ids if w != workspace_id]
    if user.workspace_roles and workspace_id in user.workspace_roles:
        user.workspace_roles = {
            k: v for k, v in user.workspace_roles.items() if k != workspace_id
        }
    await user.save()


def can_manage_workspace_members(*, user_data: UserData, workspace_id: str) -> bool:
    """
    Return whether the caller may add/remove members of ``workspace_id``.

    Tenant ``manage:sso/usso/member`` covers every workspace; a workspace
    manager holds ``manage:sso/usso/member?workspace_id=<ws>`` (e.g. via the
    workspace CEO role) and covers only that workspace. Granted roles still
    pass ``assert_assignable_workspace_role`` (no privilege escalation).
    """
    return authorization.check_access(
        user_scopes=user_data.scopes or [],
        resource_path="sso/usso/member",
        action="manage",
        filters={"workspace_id": workspace_id},
    )


def require_workspace_enabled(tenant: Tenant) -> None:
    """Raise if workspace features are disabled for the tenant."""
    if not tenant.config.workspace.enabled:
        raise BadRequestError(
            error_code="workspace_not_enabled",
            detail="Workspace is not enabled for this tenant.",
            message={
                "en": "Workspace is not enabled for this tenant.",
                "fa": "قابلیت فضای کاری در این سامانه فعال نیست.",
            },
        )


def require_workspace_manage(*, user_data: UserData, workspace_id: str) -> None:
    """Raise if the caller cannot manage the workspace."""
    if not authorization.check_access(
        user_scopes=user_data.scopes or [],
        resource_path="sso/usso/workspace",
        action="manage",
        filters={"workspace_id": workspace_id},
    ):
        raise ForbiddenError(
            error_code="workspace_manage_denied",
            detail="You do not have manage access to this workspace",
            message={
                "en": "You do not have manage access to this workspace.",
                "fa": "دسترسی ندارید.",
            },
        )


def require_workspace_manage_on_target_or_ancestor(
    *,
    user_data: UserData,
    workspace: Workspace,
) -> None:
    """Allow manage on the target workspace or any of its ancestors."""
    candidates = [workspace.uid, *(workspace.ancestor_ids or [])]
    for workspace_id in candidates:
        if authorization.check_access(
            user_scopes=user_data.scopes or [],
            resource_path="sso/usso/workspace",
            action="manage",
            filters={"workspace_id": workspace_id},
        ):
            return
    raise ForbiddenError(
        error_code="workspace_manage_denied",
        detail="You do not have manage access to this workspace",
        message={
            "en": "You do not have manage access to this workspace.",
            "fa": "دسترسی ندارید.",
        },
    )


def has_unscoped_workspace_access(
    *, user_scopes: list[str] | None, action: str = "read"
) -> bool:
    """
    Return whether caller has unscoped access on ``sso/usso/workspace``.

    Parent-scoped ``…:sso/usso/workspace?workspace_id=...`` does not qualify.
    ``manage`` / ``admin`` / ``*:*`` all satisfy ``action="read"``.
    """
    return authorization.check_access(
        user_scopes=user_scopes or [],
        resource_path="sso/usso/workspace",
        action=action,
        filters=None,
    )


def has_system_workspace_admin(*, user_scopes: list[str] | None) -> bool:
    """
    Return whether caller has unscoped admin on sso/usso/workspace.

    Parent-scoped ``admin:sso/usso/workspace?workspace_id=...`` does not qualify.
    """
    return has_unscoped_workspace_access(user_scopes=user_scopes, action="admin")


def can_list_tenant_workspaces(
    *,
    user: object | None,
    user_data: UserData,
) -> bool:
    """
    Return whether the caller may list every workspace in the tenant.

    Tenant ``admin`` role, unscoped workspace read/manage, and ``*:*``
    qualify. Membership-only users do not. Organization-specific admin
    roles should grant ``manage:sso/usso/workspace`` (or equivalent) via scopes.
    """
    roles = {
        str(role).lower()
        for role in (
            *(getattr(user, "roles", None) or []),
            *(getattr(user_data, "roles", None) or []),
        )
    }
    if "admin" in roles:
        return True
    return has_unscoped_workspace_access(user_scopes=user_data.scopes or [])


async def require_workspace_active(
    *,
    tenant_id: str,
    workspace_id: str,
) -> Workspace:
    """Raise if the workspace is missing or not active."""
    workspace = await Workspace.find_one({
        "uid": workspace_id,
        "tenant_id": tenant_id,
        "is_deleted": False,
    })
    if workspace is None:
        raise NotFoundError(
            error_code="workspace_not_found",
            detail="Workspace not found",
            message={
                "en": "Workspace not found.",
                "fa": "فضای کاری پیدا نشد.",
            },
        )
    if not workspace.is_active:
        raise ForbiddenError(
            error_code="workspace_not_active",
            detail="Workspace is not active",
            message={
                "en": "This workspace is not active yet.",
                "fa": "این فضای کاری هنوز فعال نیست.",
            },
        )
    return workspace


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.tz)
    return dt


async def _expire_if_needed(invitation: WorkspaceInvitation) -> WorkspaceInvitation:
    """Mark pending invitation expired when past expires_at."""
    if invitation.status == InvitationStatus.PENDING and _ensure_aware(
        invitation.expires_at
    ) <= datetime.now(timezone.tz):
        invitation.status = InvitationStatus.EXPIRED
        await invitation.save()
    return invitation


async def create_workspace_invitation(
    *,
    tenant: Tenant,
    user_data: UserData,
    workspace_id: str,
    data: WorkspaceInvitationCreateSchema,
) -> WorkspaceInvitation:
    """Invite a user to a workspace (manage on target or ancestor)."""
    require_workspace_enabled(tenant)
    workspace = await require_workspace_active(
        tenant_id=tenant.uid, workspace_id=workspace_id
    )
    require_workspace_manage_on_target_or_ancestor(
        user_data=user_data, workspace=workspace
    )

    invitee = await User.get_item(uid=data.invited_id, tenant_id=tenant.uid)
    if invitee is None:
        raise NotFoundError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )

    if data.invited_id == user_data.user_id:
        raise BadRequestError(
            error_code="cannot_invite_self",
            detail="Cannot invite yourself",
            message={
                "en": "You cannot invite yourself.",
                "fa": "نمی‌توانید خودتان را دعوت کنید.",
            },
        )

    if workspace_id in (invitee.workspace_ids or []):
        raise BadRequestError(
            error_code="already_workspace_member",
            detail="User is already a workspace member",
            message={
                "en": "User is already a member of this workspace.",
                "fa": "این کاربر هم‌اکنون عضو این فضای کاری است.",
            },
        )

    await assert_assignable_workspace_role(
        tenant=tenant,
        user_data=user_data,
        workspace_id=workspace_id,
        role_name=data.role,
    )

    existing = await WorkspaceInvitation.find_one({
        "tenant_id": tenant.uid,
        "workspace_id": workspace_id,
        "invited_id": data.invited_id,
        "status": InvitationStatus.PENDING,
        "is_deleted": False,
    })
    if existing:
        existing = await _expire_if_needed(existing)
        if existing.status == InvitationStatus.PENDING:
            raise BadRequestError(
                error_code="invitation_already_pending",
                detail="A pending invitation already exists",
                message={
                    "en": "A pending invitation already exists for this user.",
                    "fa": "دعوتنامهٔ در انتظار برای این کاربر از قبل وجود دارد.",
                },
            )

    expires_in_days = data.expires_in_days or DEFAULT_INVITATION_EXPIRES_IN_DAYS
    invitation = WorkspaceInvitation(
        tenant_id=tenant.uid,
        user_id=user_data.user_id,
        workspace_id=workspace_id,
        invited_id=data.invited_id,
        invited_by=user_data.user_id,
        role=data.role,
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.tz) + timedelta(days=expires_in_days),
    )
    await invitation.save()
    return invitation


async def list_workspace_invitations(
    *,
    tenant: Tenant,
    user_data: UserData,
    workspace_id: str,
    status: InvitationStatus | None,
    offset: int,
    limit: int,
) -> tuple[list[WorkspaceInvitation], int]:
    """List invitations for a workspace (manage on target or ancestor)."""
    require_workspace_enabled(tenant)
    workspace = await Workspace.find_one({
        "uid": workspace_id,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if workspace is None:
        raise NotFoundError(
            error_code="workspace_not_found",
            detail="Workspace not found",
            message={
                "en": "Workspace not found.",
                "fa": "فضای کاری پیدا نشد.",
            },
        )
    require_workspace_manage_on_target_or_ancestor(
        user_data=user_data, workspace=workspace
    )

    query: dict = {
        "tenant_id": tenant.uid,
        "workspace_id": workspace_id,
        "is_deleted": False,
    }
    if status is not None:
        query["status"] = status

    total = await WorkspaceInvitation.find(query).count()
    items = (
        await WorkspaceInvitation
        .find(query)
        .sort([("created_at", -1)])
        .skip(offset)
        .limit(limit)
        .to_list()
    )
    for item in items:
        await _expire_if_needed(item)
    return items, total


async def list_my_invitations(
    *,
    tenant: Tenant,
    user_data: UserData,
    status: InvitationStatus | None,
    offset: int,
    limit: int,
) -> tuple[list[WorkspaceInvitation], int]:
    """List invitations addressed to the current user."""
    require_workspace_enabled(tenant)

    query: dict = {
        "tenant_id": tenant.uid,
        "invited_id": user_data.user_id,
        "is_deleted": False,
    }
    if status is not None:
        query["status"] = status

    total = await WorkspaceInvitation.find(query).count()
    items = (
        await WorkspaceInvitation
        .find(query)
        .sort([("created_at", -1)])
        .skip(offset)
        .limit(limit)
        .to_list()
    )
    for item in items:
        await _expire_if_needed(item)
    return items, total


async def respond_to_invitation(
    *,
    tenant: Tenant,
    user_data: UserData,
    invitation_uid: str,
    status: InvitationStatus,
) -> WorkspaceInvitation:
    """Accept or reject a pending invitation addressed to the current user."""
    require_workspace_enabled(tenant)

    if status not in (InvitationStatus.ACCEPTED, InvitationStatus.REJECTED):
        raise BadRequestError(
            error_code="invalid_invitation_status",
            detail="Status must be accepted or rejected",
            message={
                "en": "Status must be accepted or rejected.",
                "fa": "وضعیت فقط می‌تواند قبول یا رد باشد.",
            },
        )

    invitation = await WorkspaceInvitation.find_one({
        "uid": invitation_uid,
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if invitation is None:
        raise NotFoundError(
            error_code="invitation_not_found",
            detail="Invitation not found",
            message={
                "en": "Invitation not found.",
                "fa": "دعوتنامه پیدا نشد.",
            },
        )

    if invitation.invited_id != user_data.user_id:
        raise ForbiddenError(
            error_code="invitation_access_denied",
            detail="This invitation is not addressed to you",
            message={
                "en": "This invitation is not addressed to you.",
                "fa": "دسترسی ندارید.",
            },
        )

    invitation = await _expire_if_needed(invitation)
    if invitation.status != InvitationStatus.PENDING:
        raise BadRequestError(
            error_code="invitation_not_pending",
            detail=f"Invitation is {invitation.status}",
            message={
                "en": "This invitation is no longer pending.",
                "fa": "این دعوتنامه دیگر در انتظار نیست.",
            },
        )

    if status == InvitationStatus.REJECTED:
        invitation.status = InvitationStatus.REJECTED
        await invitation.save()
        return invitation

    await require_workspace_active(
        tenant_id=tenant.uid, workspace_id=invitation.workspace_id
    )

    user = await User.get_item(uid=user_data.user_id, tenant_id=tenant.uid)
    if user is None:
        raise NotFoundError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )

    await _add_user_to_workspace(user=user, workspace_id=invitation.workspace_id)
    roles = list((user.workspace_roles or {}).get(invitation.workspace_id, []))
    if invitation.role not in roles:
        user.workspace_roles = {
            **(user.workspace_roles or {}),
            invitation.workspace_id: [*roles, invitation.role],
        }
        await user.save()

    invitation.status = InvitationStatus.ACCEPTED
    invitation.joined_at = datetime.now(timezone.tz)
    await invitation.save()
    return invitation


async def search_users_by_identifier_prefix(
    *,
    tenant: Tenant,
    user_data: UserData,
    workspace_id: str,
    identifier: str,
    identifier_type: AuthIdentifier | None,
    offset: int,
    limit: int,
) -> tuple[list[UserSearchResultSchema], int]:
    """
    Prefix-search users by identifier for workspace invitation.

    Requires manage on the workspace (or ancestor),
    tenant.workspace.user_search_enabled, and searchable flags.
    """
    require_workspace_enabled(tenant)
    workspace = await require_workspace_active(
        tenant_id=tenant.uid, workspace_id=workspace_id
    )
    require_workspace_manage_on_target_or_ancestor(
        user_data=user_data, workspace=workspace
    )

    if not tenant.config.workspace.user_search_enabled:
        raise BadRequestError(
            error_code="user_search_not_enabled",
            detail="User search is not enabled for this tenant",
            message={
                "en": "User search is not enabled for this tenant.",
                "fa": "جستجوی کاربر در این سامانه فعال نیست.",
            },
        )

    prefix = identifier.strip()
    if len(prefix) < 2:
        raise BadRequestError(
            error_code="search_prefix_too_short",
            detail="Identifier prefix must be at least 2 characters",
            message={
                "en": "Enter at least 2 characters to search.",
                "fa": "برای جستجو حداقل ۲ نویسه وارد کنید.",
            },
        )

    id_query: dict = {
        "tenant_id": tenant.uid,
        "is_deleted": False,
        "is_active": True,
        "searchable": True,
        "identifier": {
            "$regex": f"^{re.escape(prefix)}",
            "$options": "i",
        },
    }
    if identifier_type is not None:
        id_query["type"] = identifier_type

    matched_identifiers = await UserIdentifier.find(id_query).to_list()
    if not matched_identifiers:
        return [], 0

    by_user: dict[str, UserIdentifier] = {}
    for ident in matched_identifiers:
        by_user.setdefault(ident.user_id, ident)

    users = await User.find({
        "uid": {"$in": list(by_user.keys())},
        "tenant_id": tenant.uid,
        "is_deleted": False,
        "searchable": True,
    }).to_list()
    users_by_uid = {u.uid: u for u in users}

    results: list[UserSearchResultSchema] = []
    for user_id, ident in by_user.items():
        user = users_by_uid.get(user_id)
        if user is None:
            continue
        results.append(
            UserSearchResultSchema(
                uid=user.uid,
                name=user.name,
                avatar_url=user.avatar_url,
                matched_type=ident.type,
                matched_identifier=ident.identifier,
            )
        )

    total = len(results)
    page = results[offset : offset + limit]
    return page, total
