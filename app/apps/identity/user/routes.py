"""
User management API routes.

This module provides endpoints for user management including CRUD operations,
user identifiers, credentials, passkeys, and impersonation.
"""

from datetime import datetime

from fastapi import APIRouter, Query, Request
from fastapi_mongo_base.audit.context import audit_actor_scope
from fastapi_mongo_base.schemas import PaginatedResponse
from fastapi_mongo_base.utils import timezone
from usso import UserData

from server.config import Settings
from server.exceptions import (
    AccountAlreadyExistsError,
    BadRequestError,
    ForbiddenError,
    NotFoundError,
)
from utils.net import get_client_ip
from utils.usso_routes import AbstractTenantUSSORouter

from ..auth.enums import AuthIdentifier, AuthSecret, LoginStatus
from ..auth.schemas import Identifier
from ..auth.services import build_login_response, require_secure_token
from . import credential_services, impersonation, models, passkey, schemas, services


class UserRouter(AbstractTenantUSSORouter):
    """
    Router for user management endpoints.

    Provides CRUD operations for users with additional endpoints for
    identifiers, credentials, passkeys, and impersonation.
    """

    model = models.User
    schema = schemas.UserResponse
    namespace = "sso"
    # Service name is project name: usso -- service = "usso"
    resource = "user"

    def config_routes(self, **kwargs: object) -> None:
        """Configure user routes including custom endpoints."""
        super().config_routes(**kwargs)

        self.router.add_api_route(
            "/{uid}/impersonate",
            self.impersonate_user,
            methods=["POST"],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/impersonate/otp",
            self.impersonate_otp_challenge,
            methods=["POST"],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/impersonate/otp/verify",
            self.impersonate_otp_verify,
            methods=["POST"],
            status_code=200,
        )

        self.router.add_api_route(
            "/{uid}/identifiers",
            self.list_identifiers,
            methods=["GET"],
            response_model=PaginatedResponse[schemas.UserIdentifierSchema],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/identifiers",
            self.create_identifier,
            methods=["POST"],
            response_model=schemas.UserIdentifierSchema,
            status_code=201,
        )
        self.router.add_api_route(
            "/{uid}/identifiers/{identifier_id}",
            self.update_identifier,
            methods=["PATCH"],
            response_model=schemas.UserIdentifierSchema,
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/identifiers/{identifier_id}",
            self.delete_identifier,
            methods=["DELETE"],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/identifiers/{identifier_id}/resend",
            self.resend_verification,
            methods=["POST"],
            status_code=200,
        )

        self.router.add_api_route(
            "/{uid}/credentials",
            self.list_credentials,
            methods=["GET"],
            response_model=PaginatedResponse[schemas.CredentialResponseSchema],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/credentials",
            self.create_credential,
            methods=["POST"],
            response_model=schemas.CredentialResponseSchema,
            status_code=201,
        )
        self.router.add_api_route(
            "/{uid}/credentials/{credential_id}",
            self.delete_credential,
            methods=["DELETE"],
            status_code=200,
        )
        self.router.add_api_route(
            "/{uid}/credentials/{credential_id}/reset",
            self.reset_credential,
            methods=["POST"],
            status_code=200,
        )

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        created_at_from: datetime | None = None,
        created_at_to: datetime | None = None,
        identifier_type: schemas.AuthIdentifier | None = None,
        identifier: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        is_limited: bool | None = None,
        name_like: str | None = None,
        workspace_name_like: str | None = None,
    ) -> PaginatedResponse:
        """
        List users with filtering and pagination.

        Args:
            request: The FastAPI request object.
            offset: Pagination offset.
            limit: Maximum number of items to return.
            created_at_from: Filter users created after this date.
            created_at_to: Filter users created before this date.
            identifier_type: Filter by identifier type.
            identifier: Filter by identifier value.
            role: Filter by role name.
            is_active: Filter by active status.
            is_limited: Filter by limited status.
            name_like: Case-insensitive substring match on display name.
            workspace_name_like: Case-insensitive substring match on a
                membership workspace name; resolves matching workspace uids
                then filters ``workspace_ids``.

        Returns:
            Paginated response with user list.

        """
        from apps.access_control.workspace.models import Workspace

        user = await self.get_user(request)
        extra: dict[str, object] = {}
        if isinstance(name_like, str) and name_like.strip():
            extra["name_like"] = name_like.strip()
        if isinstance(workspace_name_like, str) and workspace_name_like.strip():
            workspaces = await Workspace.get_query(
                tenant_id=user.tenant_id,
                name_like=workspace_name_like.strip(),
            ).to_list()
            # Always set the filter (including empty) so unmatched names
            # return zero users instead of silently ignoring the filter.
            extra["workspace_ids_in"] = [workspace.uid for workspace in workspaces]
        result = await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            created_at_from=created_at_from,
            created_at_to=created_at_to,
            identifier_type=identifier_type,
            identifier=identifier,
            role=role,
            is_active=is_active,
            is_limited=is_limited,
            **extra,
        )
        if user is not None:
            await services.attach_user_list_directory(
                result.items, tenant_id=user.tenant_id
            )
        return result

    async def retrieve_item(self, request: Request, uid: str) -> schemas.UserResponse:
        """
        Retrieve a single user by ID.

        Args:
            request: The FastAPI request object.
            uid: User unique identifier.

        Returns:
            User detailed schema.

        """
        user = await self.get_user(request)
        item: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self.authorize(action="read", user=user, filter_data=item.model_dump())
        return await item.to_detailed_schema()

    async def create_item(
        self, request: Request, data: schemas.UserCreateSchema
    ) -> schemas.UserResponse:
        """
        Create a new user.

        Args:
            request: The FastAPI request object.
            data: User creation schema data.

        Returns:
            Created user detailed schema.

        Raises:
            ResourceError: If user already exists or creation fails.

        """
        from apps.identity.auth.schemas import LoginRequest

        tenant = await self.get_tenant(request=request)
        actor = await self.get_user(request)
        await self.authorize(action="create", user=actor, filter_data=data.model_dump())
        await services.assert_assignable_tenant_roles(
            tenant_id=tenant.uid,
            user_data=actor,
            role_names=data.roles,
        )

        login_request = LoginRequest(
            type=data.identifier_type,
            identifier=data.identifier,
        )

        existing_user = await services.find_user(
            identifier=login_request,
            tenant_id=tenant.uid,
            tenant=tenant,
        )
        if existing_user:
            raise AccountAlreadyExistsError(detail="User already exists")

        with audit_actor_scope(actor):
            user = await services.create_user(
                login=login_request,
                tenant=tenant,
                record_audit=False,
            )
            if not user:
                raise BadRequestError(
                    error_code="registration_failed",
                    detail="Registration failed",
                    message={
                        "en": "Registration failed. Check your details.",
                        "fa": "ثبت‌نام انجام نشد. اطلاعات را بررسی کنید.",
                    },
                )

            user.roles = data.roles
            user.name = data.name
            # This route is restricted to user administrators. Accounts created
            # explicitly by an administrator must not enter the registration
            # approval flow as inactive users.
            user.is_active = True
            user.meta_data = data.meta_data
            await user.save()
            if services.is_trusted_messenger_link(
                identifier_type=data.identifier_type, caller=actor
            ):
                # create_user always sets current_identifier to the primary one.
                user.current_identifier.verified_at = datetime.now(timezone.tz)
                await user.current_identifier.save()
            if data.national_id:
                await models.UserIdentifier(
                    tenant_id=tenant.uid,
                    user_id=user.uid,
                    type=AuthIdentifier.NATIONAL_ID,
                    identifier=data.national_id,
                ).save()
            await services.upsert_admin_profile(
                user=user,
                first_name=data.first_name,
                last_name=data.last_name,
            )
            await services.upsert_admin_kyc(user=user, birth_date=data.birth_date)
            await services.record_user_created(user)
        return await user.to_detailed_schema()

    async def _authorize_user_change(
        self,
        *,
        action: str,
        user: UserData | None,
        target: models.User,
        new_scopes: list[str] | None = None,
    ) -> None:
        """Usual scope check plus: never change a user with higher access."""
        if user is None:
            raise ForbiddenError(detail="An authenticated actor is required")
        await self.authorize(action=action, user=user, filter_data=target.model_dump())
        await services.assert_manageable_user(
            actor=user, target=target, new_scopes=new_scopes
        )

    async def update_item(
        self, request: Request, uid: str, data: schemas.UserUpdateSchema
    ) -> schemas.UserResponse:
        """
        Update an existing user.

        Args:
            request: The FastAPI request object.
            uid: User unique identifier.
            data: User update schema data.

        Returns:
            Updated user detailed schema.

        """
        user = await self.get_user(request)
        data_dict = data.model_dump(exclude_unset=True)
        profile_update = {
            key: data_dict.pop(key)
            for key in ("first_name", "last_name")
            if key in data_dict
        }
        birth_date_provided = "birth_date" in data_dict
        birth_date = data_dict.pop("birth_date", None)
        item: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update",
            user=user,
            target=item,
            new_scopes=data_dict.get("scopes"),
        )
        if "roles" in data_dict:
            await services.assert_assignable_tenant_roles(
                tenant_id=user.tenant_id,
                user_data=user,
                role_names=data_dict.get("roles") or [],
            )

        with audit_actor_scope(user):
            item = await self.model.update_item(item, data_dict)
        if profile_update:
            await services.upsert_admin_profile(user=item, **profile_update)
        if birth_date_provided:
            await services.upsert_admin_kyc(user=item, birth_date=birth_date)
        await self._propagate_permission_sessions(item=item, data_dict=data_dict)
        return await item.to_detailed_schema()

    async def _propagate_permission_sessions(
        self,
        *,
        item: models.User,
        data_dict: dict[str, object],
    ) -> None:
        """
        Refresh sessions when role/scope/membership fields change.

        Deactivation revokes every live session at once (forced sign-out).
        """
        if data_dict.get("is_active") is False:
            await models.AuthSession.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}})
            return
        permission_fields = ["roles", "scopes", "workspace_roles", "is_active"]
        if not any(field in data_dict for field in permission_fields):
            return
        workspaces_to_update: list[str | None] = []
        if "roles" in data_dict or "scopes" in data_dict or "is_active" in data_dict:
            workspaces_to_update.append(None)
            workspaces_to_update.extend(item.workspace_ids or [])
        if "workspace_roles" in data_dict and data_dict.get("workspace_roles"):
            workspaces_to_update.extend(data_dict["workspace_roles"].keys())
        if not workspaces_to_update:
            workspaces_to_update = [None]
        seen: set[str | None] = set()
        unique_workspaces: list[str | None] = []
        for workspace_id in workspaces_to_update:
            if workspace_id in seen:
                continue
            seen.add(workspace_id)
            unique_workspaces.append(workspace_id)
        for workspace_id in unique_workspaces:
            await item.update_permissions_and_sessions(workspace_id=workspace_id)

    async def delete_item(self, request: Request, uid: str) -> schemas.UserResponse:
        """
        Hard-delete a user (cascade soft-delete of belongings).

        Args:
            request: The FastAPI request object.
            uid: User unique identifier.

        Returns:
            Deleted user detailed schema.

        """
        user = await self.get_user(request)
        if uid == user.uid:
            raise BadRequestError(
                error_code="cannot_delete_self",
                detail="Cannot delete your own account",
                message={
                    "en": "You cannot delete your own account.",
                    "fa": "امکان حذف حساب خودتان وجود ندارد.",
                },
            )
        item: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(action="delete", user=user, target=item)
        with audit_actor_scope(user):
            item = await self.model.hard_delete(item)
        return await item.to_detailed_schema()

    async def impersonate_user(
        self,
        request: Request,
        uid: str,
        data: schemas.ImpersonateRequest | None = None,
    ) -> schemas.UserResponse:
        """
        Impersonate a user as if they completed a normal login.

        ``mode=readonly`` strips write scopes from the issued JWT. Audit claims
        always include ``impersonated_by``. Use workspace-login afterwards to
        enter another workspace as that user.
        """
        body = data or schemas.ImpersonateRequest()
        caller, target, tenant = await self._prepare_impersonation(request, uid)
        return await self._issue_impersonation_response(
            request=request,
            tenant=tenant,
            caller_uid=caller.uid,
            target=target,
            mode=body.mode,
            consent="admin",
        )

    async def impersonate_otp_challenge(
        self,
        request: Request,
        uid: str,
        data: schemas.ImpersonateOTPRequest,
    ) -> dict:
        """Send OTP to the target user for consented impersonation."""
        caller, target, tenant = await self._prepare_impersonation(request, uid)
        return await impersonation.send_impersonation_otp(
            user=target,
            tenant=tenant,
            requested_by=caller.uid,
            mode=data.mode,
            identifier_type=data.identifier_type,
            origin=request.headers.get("origin"),
        )

    async def impersonate_otp_verify(
        self,
        request: Request,
        uid: str,
        data: schemas.ImpersonateOTPVerifyRequest,
    ) -> schemas.UserResponse:
        """Verify user OTP and issue an impersonation session."""
        caller, target, tenant = await self._prepare_impersonation(request, uid)
        await impersonation.verify_impersonation_otp(
            user=target,
            tenant=tenant,
            requested_by=caller.uid,
            mode=data.mode,
            otp=data.otp,
        )
        return await self._issue_impersonation_response(
            request=request,
            tenant=tenant,
            caller_uid=caller.uid,
            target=target,
            mode=data.mode,
            consent="otp",
        )

    async def _prepare_impersonation(
        self, request: Request, uid: str
    ) -> tuple[object, models.User, object]:
        user = await self.get_user(request)
        if user is None:
            raise ForbiddenError(
                error_code="authentication_required",
                detail="Authentication required",
                message={
                    "en": "You must be signed in.",
                    "fa": "برای این کار باید وارد شوید.",
                },
            )
        if uid == user.uid:
            raise BadRequestError(
                error_code="cannot_impersonate_self",
                detail="Cannot impersonate yourself",
                message={
                    "en": "You cannot impersonate your own account.",
                    "fa": "امکان ورود به حساب خودتان وجود ندارد.",
                },
            )

        impersonated_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        if impersonated_user.is_deleted:
            raise NotFoundError(
                error_code="user_not_found",
                detail="User not found",
                message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
            )

        await self._authorize_user_change(
            action="admin", user=user, target=impersonated_user
        )
        tenant = await self.get_tenant(request=request)
        return user, impersonated_user, tenant

    async def _issue_impersonation_response(
        self,
        *,
        request: Request,
        tenant: object,
        caller_uid: str,
        target: models.User,
        mode: schemas.ImpersonationMode,
        consent: str,
    ) -> object:
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent")
        refresh_payload = tenant.refresh_auth(request)
        session = await impersonation.create_impersonation_session(
            user=target,
            tenant=tenant,
            impersonated_by=caller_uid,
            mode=mode,
            consent=consent,  # type: ignore[arg-type]
            user_agent=user_agent,
            ip=client_ip,
            parent_session_id=(refresh_payload.session_id if refresh_payload else None),
        )
        payloads = impersonation.create_impersonation_tokens(
            user=target,
            tenant=tenant,
            session=session,
            url=request.url,
        )
        return build_login_response(
            request=request,
            tenant=tenant,
            payloads=payloads,
            status=LoginStatus.COMPLETED,
        )

    # =============================================================================
    # IDENTIFIERS Management - RESTful endpoints
    # =============================================================================

    async def list_identifiers(
        self,
        request: Request,
        uid: str,
        offset: int = Query(0, ge=0, description="Number of items to skip"),
        limit: int = Query(50, ge=1, le=100, description="Number of items to return"),
    ) -> PaginatedResponse[schemas.UserIdentifierSchema]:
        """List all identifiers for a user."""
        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self.authorize(
            action="read", user=user, filter_data=target_user.model_dump()
        )

        # Get all identifiers (they're usually not many per user)
        all_identifiers = await target_user.get_identifiers()

        # Apply pagination
        total_count = len(all_identifiers)
        paginated_identifiers = all_identifiers[offset : offset + limit]

        items = [
            schemas.UserIdentifierSchema.model_validate(identifier)
            for identifier in paginated_identifiers
        ]

        return PaginatedResponse(
            items=items,
            total=total_count,
            offset=offset,
            limit=limit,
        )

    async def create_identifier(
        self, request: Request, uid: str, data: schemas.UserIdentifierCreateSchema
    ) -> schemas.UserIdentifierSchema:
        """Add a new identifier to a user."""
        # Check if verification is needed based on policy
        tenant = await self.get_tenant(request)

        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        trusted_messenger_link = services.is_trusted_messenger_link(
            identifier_type=data.type, caller=user
        )

        # Check if identifier already exists
        existing = await models.UserIdentifier.find_one({
            "tenant_id": target_user.tenant_id,
            "type": data.type,
            "identifier": data.identifier,
            "is_deleted": False,
        })
        if existing:
            # Re-linking by the trusted bot heals ids linked before trusted
            # links were verified and refreshes the messenger username.
            if trusted_messenger_link and existing.user_id == target_user.uid:
                meta_data = services.apply_messenger_profile(
                    current=existing.meta_data, incoming=data.meta_data
                )
                if existing.verified_at is None or meta_data != existing.meta_data:
                    existing.verified_at = existing.verified_at or datetime.now(
                        timezone.tz
                    )
                    existing.meta_data = meta_data
                    await existing.save()
            raise AccountAlreadyExistsError(detail="Identifier already exists")

        # Create new identifier
        identifier = models.UserIdentifier(
            tenant_id=target_user.tenant_id,
            user_id=target_user.uid,
            type=data.type,
            identifier=data.identifier,
            is_primary=data.is_primary,
            verified_at=datetime.now(timezone.tz) if trusted_messenger_link else None,
            meta_data=(
                services.apply_messenger_profile(current=None, incoming=data.meta_data)
                if trusted_messenger_link
                else None
            ),
        )
        await identifier.save()

        # Check if verification is needed based on policy
        needs_verification = services.needs_verification(
            identifier=Identifier.model_validate(identifier.model_dump()),
            method=None,
            tenant=tenant,
        )

        # Send verification if needed
        if needs_verification and user.user_id == target_user.user_id:
            # Determine channel type based on identifier type
            from apps.tenant.messaging.channels.base import AbstractChannel

            from ..auth.schemas import OTPRequest
            from ..auth.services import create_otp

            preferred_channel = "email" if data.type == AuthIdentifier.EMAIL else "sms"
            channel_type = AbstractChannel.resolve_channel_type(
                typ=preferred_channel, tenant=tenant
            )

            otp_request = OTPRequest(
                channel_type=channel_type,
                identifier=data.identifier,
                type=data.type,
            )

            # Generate and send verification code
            origin = (
                (request.headers.get("origin") or "")
                .removeprefix("https://")
                .removeprefix("http://")
            )
            await create_otp(
                otp_request=otp_request,
                tenant=tenant,
                origin=origin,
            )

        return schemas.UserIdentifierSchema(**identifier.model_dump())

    async def update_identifier(
        self,
        request: Request,
        uid: str,
        identifier_id: str,
        data: schemas.UserIdentifierUpdateSchema,
    ) -> schemas.UserIdentifierSchema:
        """Update an existing identifier."""
        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        identifier = await models.UserIdentifier.get_by_uid(identifier_id)
        if not identifier or identifier.user_id != target_user.uid:
            raise NotFoundError(
                detail="Identifier not found",
                message={"en": "Identifier not found", "fa": "اطلاعات تماس پیدا نشد."},
            )

        # Update fields
        update_data = data.model_dump(exclude_unset=True)
        if data.identifier is not None:
            validated = schemas.UserIdentifierSchema.model_validate({
                **identifier.model_dump(),
                "identifier": data.identifier,
            })
            existing = await models.UserIdentifier.find_one({
                "tenant_id": target_user.tenant_id,
                "type": identifier.type,
                "identifier": validated.identifier,
                "uid": {"$ne": identifier.uid},
                "is_deleted": False,
            })
            if existing:
                raise AccountAlreadyExistsError(detail="Identifier already exists")
            update_data["identifier"] = validated.identifier
        for field, value in update_data.items():
            setattr(identifier, field, value)

        await identifier.save()
        return schemas.UserIdentifierSchema(**identifier.model_dump())

    async def delete_identifier(
        self, request: Request, uid: str, identifier_id: str
    ) -> models.UserIdentifier:
        """Delete an identifier."""
        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        identifier = await models.UserIdentifier.get_by_uid(identifier_id)
        if not identifier or identifier.user_id != target_user.uid:
            raise NotFoundError(
                detail="Identifier not found",
                message={"en": "Identifier not found", "fa": "اطلاعات تماس پیدا نشد."},
            )

        # Check if it's the last identifier
        identifiers = await target_user.get_identifiers()
        if len(identifiers) <= 1:
            raise BadRequestError(
                error_code="cannot_delete_last_identifier",
                detail="Cannot delete the last identifier",
                message={
                    "en": "Cannot delete the last identifier",
                    "fa": "نمی‌توانید آخرین راه تماس خود را حذف کنید.",
                },
            )

        await identifier.delete()
        return identifier

    async def verify_identifier(
        self,
        request: Request,
        uid: str,
        identifier_id: str,
        data: schemas.VerificationRequestSchema,
    ) -> schemas.UserIdentifierSchema:
        """Verify an identifier with a code."""
        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        identifier = await models.UserIdentifier.get_by_uid(identifier_id)
        if not identifier or identifier.user_id != target_user.uid:
            raise NotFoundError(
                detail="Identifier not found",
                message={"en": "Identifier not found", "fa": "اطلاعات تماس پیدا نشد."},
            )

        # Validate verification code
        tenant = await self.get_tenant(request)

        # Check if verification code exists and is valid
        method = (
            AuthSecret.EMAIL_OTP if identifier.type == "email" else AuthSecret.PHONE_OTP
        )
        verification_credential = await models.Credential.find_one({
            "tenant_id": tenant.uid,
            "user_id": target_user.uid,
            "method": method,
            "secret": data.code,
            "is_deleted": False,
            "expires_at": {"$gt": datetime.now(timezone.tz)},
        })

        if not verification_credential:
            raise BadRequestError(
                error_code="invalid_verification_code",
                detail="Invalid or expired verification code",
                message={
                    "en": "Invalid or expired verification code",
                    "fa": "کد تأیید اشتباه است یا منقضی شده.",
                },
            )

        # Mark identifier as verified
        identifier.verified_at = datetime.now(timezone.tz)
        await identifier.save()

        # Delete the verification credential (single use)
        await verification_credential.delete()

        # Update user sessions if this verification affects user activation
        await target_user.update_permissions_and_sessions()

        return schemas.UserIdentifierSchema(**identifier.model_dump())

    async def resend_verification(
        self, request: Request, uid: str, identifier_id: str
    ) -> None:
        """Resend verification code for an identifier."""
        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        identifier = await models.UserIdentifier.get_by_uid(identifier_id)
        if not identifier or identifier.user_id != target_user.uid:
            raise NotFoundError(
                detail="Identifier not found",
                message={"en": "Identifier not found", "fa": "اطلاعات تماس پیدا نشد."},
            )

        # Generate and send new verification code
        tenant = await self.get_tenant(request)

        # Create OTP request for sending verification code
        from apps.tenant.messaging.channels.base import AbstractChannel

        from ..auth.schemas import OTPRequest
        from ..auth.services import create_otp

        preferred_channel = "email" if identifier.type == "email" else "sms"
        resolved_channel = AbstractChannel.resolve_channel_type(
            typ=preferred_channel, tenant=tenant
        )
        otp_request = OTPRequest(
            channel_type=resolved_channel,
            identifier=identifier.identifier,
            type=identifier.type,
        )

        # Generate and send verification code
        origin = (
            request.headers
            .get("origin", "")
            .removeprefix("https://")
            .removeprefix("http://")
        )
        otp = await create_otp(
            otp_request=otp_request,
            tenant=tenant,
            origin=origin,
        )
        return {"otp": otp}

    # =============================================================================
    # CREDENTIALS Management - RESTful endpoints
    # =============================================================================

    async def list_credentials(
        self,
        request: Request,
        uid: str,
        offset: int = Query(0, ge=0, description="Number of items to skip"),
        limit: int = Query(50, ge=1, le=100, description="Number of items to return"),
    ) -> PaginatedResponse[schemas.CredentialResponseSchema]:
        """List all credentials for a user (without sensitive data)."""
        user = await self.get_user(request)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self.authorize(
            action="read", user=user, filter_data=target_user.model_dump()
        )

        # Get all credentials (they're usually not many per user)
        all_credentials = await target_user.get_credentials()

        # Apply pagination
        total_count = len(all_credentials)
        paginated_credentials = all_credentials[offset : offset + limit]

        items = [
            schemas.CredentialResponseSchema(**{
                **credential.model_dump(),
                "secret": None,  # Exclude sensitive data
            })
            for credential in paginated_credentials
        ]

        return PaginatedResponse(
            items=items,
            total=total_count,
            offset=offset,
            limit=limit,
        )

    async def create_credential(
        self, request: Request, uid: str, data: schemas.CredentialCreateSchema
    ) -> schemas.CredentialResponseSchema:
        """Add a new credential to a user."""
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        # Hash password if needed
        secret = data.secret
        if data.method == AuthSecret.PASSWORD:
            from utils.hasher import PasswordHasherService

            secret = PasswordHasherService().hash_password(secret)

        credential = models.Credential(
            tenant_id=target_user.tenant_id,
            user_id=target_user.uid,
            method=data.method,
            secret=secret,
            expires_at=data.expires_at,
        )
        await credential.save()

        return schemas.CredentialResponseSchema(**{
            **credential.model_dump(),
            "secret": None,
        })

    async def update_credential(
        self,
        request: Request,
        uid: str,
        credential_id: str,
        data: schemas.CredentialUpdateSchema,
    ) -> schemas.CredentialResponseSchema:
        """Update an existing credential."""
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        credential = await models.Credential.get_by_uid(credential_id)
        if not credential or credential.user_id != target_user.uid:
            raise NotFoundError(
                detail="Credential not found",
                message={"en": "Credential not found", "fa": "روش ورود پیدا نشد."},
            )

        # Update fields
        update_data = data.model_dump(exclude_unset=True)
        if (
            "secret" in update_data
            and update_data["secret"]
            and credential.method == AuthSecret.PASSWORD
        ):
            from utils.hasher import PasswordHasherService

            update_data["secret"] = PasswordHasherService().hash_password(
                update_data["secret"]
            )

        for field, value in update_data.items():
            setattr(credential, field, value)

        await credential.save()
        return schemas.CredentialResponseSchema(**{
            **credential.model_dump(),
            "secret": None,
        })

    async def delete_credential(
        self, request: Request, uid: str, credential_id: str
    ) -> models.Credential:
        """Delete a credential."""
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        credential = await models.Credential.get_by_uid(credential_id)
        if not credential or credential.user_id != target_user.uid:
            raise NotFoundError(
                detail="Credential not found",
                message={"en": "Credential not found", "fa": "روش ورود پیدا نشد."},
            )

        await credential.delete()
        return credential

    async def reset_credential(
        self, request: Request, uid: str, credential_id: str
    ) -> None:
        """Reset a specific credential (e.g., generate new TOTP secret)."""
        tenant = await self.get_tenant(request)
        user = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        target_user: models.User = await self.get_item(
            uid=uid, user_id=None, tenant_id=user.tenant_id
        )
        await self._authorize_user_change(
            action="update", user=user, target=target_user
        )

        credential = await models.Credential.get_by_uid(credential_id)
        if not credential or credential.user_id != target_user.uid:
            raise NotFoundError(
                detail="Credential not found",
                message={"en": "Credential not found", "fa": "روش ورود پیدا نشد."},
            )

        match credential.method:
            case AuthSecret.PASSWORD:
                raise BadRequestError(
                    error_code="use_password_endpoint",
                    detail="Use POST /auth/password with a secure token",
                    message={
                        "en": "Use POST /auth/password after secure verification.",
                        "fa": "پس از تأیید امن، از مسیر تنظیم رمز عبور استفاده کنید.",
                    },
                )

            case AuthSecret.TOTP:
                # Soft-delete old TOTP and return a fresh enrollment challenge.
                await credential.delete()
                return await credential_services.register_random_totp_challenge(
                    tenant, target_user, request.url.hostname
                )

            case AuthSecret.WEBAUTHN:
                # For WebAuthn, delete credential and require re-registration
                await credential.delete()

            case _:
                # For other credential types, mark as expired/deleted
                credential.is_deleted = True
                await credential.save()

        # Update user sessions to reflect credential changes
        return {
            "message": "Credential reset successfully and has been sent to the user"
        }


class IdentifierRouter(AbstractTenantUSSORouter):
    """Identifier router."""

    model = models.UserIdentifier
    schema = schemas.UserIdentifierSchema
    namespace = "sso"
    service = "usso"
    resource = "identifier"

    def __init__(self) -> None:
        """Initialize identifier router."""
        super().__init__(prefix="/identifiers", tags=["Identifiers"])

    def config_routes(self, **kwargs: object) -> None:
        """Configure identifier routes."""
        super().config_routes(update_route=False, **kwargs)

    async def create_item(
        self, request: Request, data: schemas.UserIdentifierCreateSchema
    ) -> schemas.UserIdentifierSchema:
        """Create an identifier."""
        user = await self.get_user(request)
        data = data.model_dump()
        item = await models.UserIdentifier.create_item({
            **data,
            "user_id": user.user_id,
            "tenant_id": user.tenant_id,
        })
        return item


class CredentialRouter(AbstractTenantUSSORouter):
    """Credential router."""

    model = models.Credential
    schema = schemas.CredentialResponseSchema
    namespace = "sso"
    service = "usso"
    resource = "credential"

    def __init__(self) -> None:
        """Initialize credential router."""
        super().__init__(prefix="/credentials", tags=["Credentials"])

    def config_routes(self, **kwargs: object) -> None:
        """Configure credential routes."""
        self.router.add_api_route(
            "/passkey",
            self.get_passkey_challenge,
            methods=["GET"],
            status_code=200,
        )
        self.router.add_api_route(
            "/totp",
            self.get_totp_challenge,
            methods=["GET"],
            status_code=200,
        )
        super().config_routes(update_route=False, **kwargs)
        self.router.add_api_route(
            "/passkey",
            self.create_passkey_credential,
            methods=["POST"],
            status_code=201,
        )
        self.router.add_api_route(
            "/totp",
            self.create_totp_credential,
            methods=["POST"],
            status_code=201,
        )

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=100),
    ) -> PaginatedResponse[schemas.CredentialResponseSchema]:
        """
        List user credentials with pagination.

        Args:
            request: The FastAPI request object.
            offset: Pagination offset.
            limit: Maximum number of items to return.

        Returns:
            Paginated response with credential list.

        """
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            is_active=True,
            expires_at_from=datetime.now(timezone.tz),
        )

    async def create_item(
        self, request: Request, data: schemas.CredentialCreateSchema
    ) -> schemas.CredentialResponseSchema:
        """Create a credential."""
        user = await self.get_user(request)
        data = data.model_dump()
        item = await models.Credential.create_item({
            **data,
            "user_id": user.user_id,
            "tenant_id": user.tenant_id,
        })
        return item

    async def get_passkey_challenge(self, request: Request) -> dict:
        """Generate webauthn challenge for new passkey registration."""
        tenant = await self.get_tenant(request)
        user = await self.get_user(request)
        return await credential_services.register_passkey(
            tenant,
            user,
            request.url.hostname,
            origin=request.headers.get("origin"),
        )

    async def create_passkey_credential(
        self,
        request: Request,
        # data: schemas.CredentialCreateSchema,
        data: passkey.PasskeyAssertion,
    ) -> schemas.CredentialResponseSchema:
        """Create a passkey credential."""
        tenant = await self.get_tenant(request)
        user_data = await self.get_user(request)
        target_user = await models.User.get_item(
            uid=user_data.uid, tenant_id=tenant.uid
        )
        if target_user is None:
            raise NotFoundError(
                detail="User not found",
                message={"en": "User not found", "fa": "کاربر پیدا نشد."},
            )
        item = await credential_services.verify_registration_passkey(
            tenant,
            target_user,
            data.model_dump(),
            hostname=request.url.hostname,
            origin=request.headers.get("origin"),
        )
        if item:
            return schemas.CredentialResponseSchema.model_validate(item)
        else:
            raise BadRequestError(
                error_code="passkey_registration_failed",
                detail="Passkey registration failed",
                message={
                    "en": "Passkey registration failed",
                    "fa": "ثبت کلید امنیتی انجام نشد.",
                },
            )
        return schemas.CredentialResponseSchema.model_validate(item)

    async def get_totp_challenge(self, request: Request) -> dict:
        """Generate totp challenge for new totp registration."""
        tenant = await self.get_tenant(request)
        user = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        return await credential_services.register_random_totp_challenge(
            tenant, user, request.url.hostname
        )

    async def create_totp_credential(
        self,
        request: Request,
        data: schemas.TOTPCreateSchema,
    ) -> schemas.CredentialResponseSchema:
        """Create a TOTP credential."""
        tenant = await self.get_tenant(request)
        user = await self.get_user(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        cred = await credential_services.verify_totp_challenge(
            tenant, user, data, request.url.hostname
        )
        return schemas.CredentialResponseSchema.model_validate(cred)


router = APIRouter()
router.include_router(UserRouter().router)
router.include_router(IdentifierRouter().router)
router.include_router(CredentialRouter().router)
