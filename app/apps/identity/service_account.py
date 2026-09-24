"""Shared subject binding helpers for service accounts (API keys & agents)."""

from typing import Self

from pydantic import BaseModel, Field, model_validator
from usso import UserData, authorization

from apps.identity.user.models import User
from server.exceptions import BadRequestError, ForbiddenError


class SubjectBindingMixin(BaseModel):
    """
    Ownership subject: at least one of user_id / workspace_id.

    Prefer both when the caller has an active workspace context.
    """

    user_id: str | None = None
    workspace_id: str | None = None

    @model_validator(mode="after")
    def validate_subject_at_least_one(self) -> Self:
        """Require at least one of user_id or workspace_id."""
        if self.user_id is None and self.workspace_id is None:
            msg = "At least one of user_id or workspace_id must be set"
            raise ValueError(msg)
        return self


def resolve_create_binding(
    *,
    caller: UserData,
    user_id: str | None,
    workspace_id: str | None,
) -> tuple[str | None, str | None]:
    """
    Default binding: prefer caller's user_id + workspace_id when omitted.

    If both are omitted, use the JWT subject and workspace_id (workspace may
    still be None → user-only).
    """
    if user_id is None and workspace_id is None:
        user_id = caller.uid or caller.user_id or None
        workspace_id = caller.workspace_id or None
    user_id = user_id or None
    workspace_id = workspace_id or None
    if user_id is None and workspace_id is None:
        raise BadRequestError(
            error_code="subject_required",
            detail="At least one of user_id or workspace_id must be set",
            message={
                "en": "Bind the service account to a user and/or workspace.",
                "fa": "حساب سرویس را به کاربر و/یا فضای کاری وصل کنید.",
            },
        )
    return user_id, workspace_id


def authorize_service_account_create(
    *,
    caller: UserData,
    user_id: str | None,
    workspace_id: str | None,
) -> None:
    """Authorize creating a service account for the given binding."""
    caller_uid = caller.uid or caller.user_id
    scopes = caller.scopes or []

    if workspace_id is not None:
        can_manage_workspace = authorization.check_access(
            user_scopes=scopes,
            resource_path="sso/usso/workspace",
            action="manage",
            filters={"workspace_id": workspace_id},
        )
        # Workspace-only requires manage; self-service needs user_id=caller.
        if not can_manage_workspace and (user_id is None or user_id != caller_uid):
            raise ForbiddenError(
                error_code="workspace_manage_denied",
                detail="You do not have manage access to this workspace",
                message={
                    "en": "You do not have manage access to this workspace.",
                    "fa": "دسترسی ندارید.",
                },
            )

    if (
        user_id is not None
        and user_id != caller_uid
        and not authorization.check_access(
            user_scopes=scopes,
            resource_path="sso/usso/user",
            action="manage",
        )
    ):
        raise ForbiddenError(
            error_code="user_manage_denied",
            detail="You cannot create a service account for another user",
            message={
                "en": "You cannot create a service account for another user.",
                "fa": "دسترسی ندارید.",
            },
        )


async def resolve_scope_ceiling(
    *,
    caller_user: User,
    user_id: str | None,
    workspace_id: str | None,
) -> list[str]:
    """
    Scopes the service account may be granted.

    - user + workspace → that user's effective scopes on the workspace
    - user only → that user's tenant-wide scopes
    - workspace only → caller's effective scopes on the workspace
    """
    if user_id is not None:
        target = await User.get_item(uid=user_id, tenant_id=caller_user.tenant_id)
        if target is None:
            raise BadRequestError(
                error_code="user_not_found",
                detail="User not found",
                message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
            )
        return list(await target.get_effective_scopes_for_api(workspace_id) or [])

    return list(await caller_user.get_effective_scopes_for_api(workspace_id) or [])


def assert_scopes_subset(
    *,
    requested: list[str],
    ceiling: list[str],
) -> None:
    """Raise if any requested scope is not covered by the ceiling."""
    unauthorized = [
        scope
        for scope in requested
        if not authorization.has_subset_scope(subset_scope=scope, user_scopes=ceiling)
    ]
    if unauthorized:
        detail = (
            "You cannot grant scopes that exceed the binding ceiling: "
            + ", ".join(unauthorized)
        )
        raise ForbiddenError(
            error_code="invalid_scopes",
            detail=detail,
            message={
                "en": detail,
                "fa": ("فقط می‌توانید دسترسی‌هایی بدهید که در محدودهٔ اتصال مجاز باشند."),
            },
        )


class ClientSecretFields(BaseModel):
    """Persisted client-secret hash (plaintext returned only once on create)."""

    hashed_client_secret: str | None = Field(
        default=None,
        description="Argon2/hash of OAuth client_secret",
    )
    created_by: str | None = Field(
        default=None,
        description="User uid that created this service account",
    )
