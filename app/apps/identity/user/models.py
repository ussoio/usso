"""User models."""

import asyncio
import re
from datetime import datetime
from typing import ClassVar, Self

from fastapi_mongo_base.models import (
    ASCENDING,
    IndexModel,
    TenantScopedEntity,
    TenantUserEntity,
)
from fastapi_mongo_base.utils import timezone
from fastapi_mongo_base.utils.mongo_aggregate import aggregate_to_list

from ...access_control.role.models import Role
from ...access_control.workspace.models import Workspace
from ...tenant.models import Tenant
from ..agent.models import Agent
from ..api_key.models import APIKey
from ..auth.enums import AuthSecret
from ..kyc.models import KYC
from ..legal.models import LegalAcceptance
from ..profile.models import Profile
from ..referral.models import ReferralCode
from ..session.models import AuthSession
from .schemas import (
    AuthIdentifier,
    CredentialSchema,
    UserIdentifierSchema,
    UserResponse,
    UserSchema,
)


def _normalize_identifier_search(value: str) -> str:
    """Normalize an untyped phone search while leaving national IDs untouched."""
    raw = value.strip()
    digits = "".join(character for character in raw if character.isdigit())
    if len(digits) == 11 and digits.startswith("09"):
        return f"98{digits[1:]}"
    if len(digits) == 12 and digits.startswith("98"):
        return digits
    return raw


class UserIdentifier(UserIdentifierSchema, TenantUserEntity):
    """User identifier model."""

    class Settings:
        """User identifier settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("type", ASCENDING),
                    ("identifier", ASCENDING),
                ],
                unique=True,
            ),
        ]


class Credential(CredentialSchema, TenantUserEntity):
    """Credential model."""

    class Settings:
        """Credential settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("user_id", ASCENDING),
                    ("method", ASCENDING),
                ],
                # unique True,
                # Multiple (Oauth, Webauth, OTP, ...) credentials are allowed
            ),
        ]

    @classmethod
    def get_queryset(cls, **kwargs: object) -> dict:
        """Get queryset with custom filtering."""
        expires_at_from = None
        if kwargs.get("expires_at_from") and kwargs.get("expires_at_to") is None:
            expires_at_from = kwargs.pop("expires_at_from")
        queryset = super().get_queryset(**kwargs)
        if expires_at_from:
            or_query = queryset.pop("$or", None)
            expires_at_query = [
                {"expires_at": None},
                {"expires_at": {"$gte": expires_at_from}},
            ]
            if or_query:
                queryset["$and"] = [
                    *queryset.get("$and", []),
                    {"$or": or_query},
                    {"$or": expires_at_query},
                ]
            else:
                queryset["$or"] = expires_at_query
        return queryset


class User(UserSchema, TenantScopedEntity):
    """User model."""

    @classmethod
    def get_queryset(cls, **kwargs: object) -> dict:
        """Get queryset with optional case-insensitive name / name_like filter."""
        name = kwargs.pop("name_like", None)
        if name is None:
            name = kwargs.pop("name", None)
        else:
            kwargs.pop("name", None)
        # Resolved by list_items from workspace_name_like → matching workspace uids.
        # An empty list means "no workspaces matched" and must yield zero users.
        workspace_ids_in = kwargs.pop("workspace_ids_in", None)
        queryset = super().get_queryset(**kwargs)
        if isinstance(name, str) and name.strip():
            queryset["name"] = {
                "$regex": re.escape(name.strip()),
                "$options": "i",
            }
        if workspace_ids_in is not None:
            queryset["workspace_ids"] = {"$in": list(workspace_ids_in)}
        return queryset

    async def get_tenant(self) -> Tenant:
        """Tenant for this user."""
        if not self.tenant:
            self.tenant = await Tenant.get_by_uid(self.tenant_id)
        return self.tenant

    async def get_workspaces(self) -> list[Workspace]:
        """Get workspaces for this user."""
        return await Workspace.get_query(tenant_id=self.tenant_id).to_list()

    async def get_scopes(
        self,
        workspace_id: str | None = None,
        roles: list[Role] | None = None,
    ) -> list[str] | None:
        """
        Get scopes for this user.

        Always includes direct user.scopes. Role scopes come from get_roles:
        tenant-wide roles, plus workspace roles when workspace_id is set.
        """
        scopes = set(self.scopes) if self.scopes else set()
        roles = roles if roles is not None else await self.get_roles(workspace_id)
        for role in roles:
            scopes |= set(role.scopes)
        return list(scopes)

    async def get_effective_scopes_for_api(
        self, workspace_id: str | None = None
    ) -> list[str]:
        """
        Scopes allowed for API key/agent in this context only.

        When workspace_id is None, returns tenant-wide scopes only.
        When workspace_id is set, returns tenant-wide scopes plus that
        workspace's roles; workspace scopes are expected to include
        workspace_id in the scope string (e.g. ?workspace_id={ws_id}).
        """
        scopes = await self.get_scopes(workspace_id)
        return list(scopes or [])

    async def get_roles(self, workspace_id: str | None = None) -> list[Role]:
        """
        Resolve roles for the current context.

        Always includes tenant-wide roles (user.roles, Role.workspace_id is None).
        When workspace_id is set, includes that workspace's roles plus roles from
        every active descendant the user is also a member of.
        """
        roles_by_uid: dict[str, Role] = {}

        if self.roles:
            tenant_roles = await Role.get_query(
                tenant_id=self.tenant_id,
                name_in=self.roles,
                workspace_id=None,
            ).to_list()
            for role in tenant_roles:
                roles_by_uid[role.uid] = role

        if workspace_id is not None:
            from apps.access_control.workspace.services import (
                list_membered_active_descendant_ids,
            )

            role_nodes = [
                workspace_id,
                *await list_membered_active_descendant_ids(
                    user=self, workspace_id=workspace_id
                ),
            ]
            for node_id in role_nodes:
                workspace_role_names = list(
                    (self.workspace_roles or {}).get(node_id, [])
                )
                if not workspace_role_names:
                    continue
                workspace_roles = await Role.get_query(
                    tenant_id=self.tenant_id,
                    name_in=workspace_role_names,
                    workspace_id=node_id,
                ).to_list()
                for role in workspace_roles:
                    roles_by_uid[role.uid] = role

        return list(roles_by_uid.values())

    async def get_sessions(self) -> list[AuthSession]:
        """Get sessions for this user."""
        if getattr(self, "_sessions", None):
            return self._sessions
        self._sessions = await AuthSession.get_query(
            tenant_id=self.tenant_id,
            user_id=self.uid,
        ).to_list()
        return self._sessions

    async def get_identifiers(
        self, *, not_cached: bool = False
    ) -> list[UserIdentifier]:
        """Get identifiers for this user."""
        if getattr(self, "_identifiers", None) and not not_cached:
            return self._identifiers
        self._identifiers = await UserIdentifier.get_query(
            tenant_id=self.tenant_id,
            user_id=self.uid,
        ).to_list()
        return self._identifiers

    async def get_username(self) -> str:
        """Get username for this user."""
        identifiers = await self.get_identifiers()
        email_identifier = next((i for i in identifiers if i.type == "email"), None)
        phone_identifier = next((i for i in identifiers if i.type == "phone"), None)
        username_identifier = next(
            (i for i in identifiers if i.type == "username"), None
        )
        return (
            username_identifier.identifier
            if username_identifier
            else email_identifier.identifier
            if email_identifier
            else phone_identifier.identifier
            if phone_identifier
            else self.uid
        )

    async def get_credentials(
        self, method: AuthSecret | None = None, *, not_cached: bool = False
    ) -> list[Credential]:
        """Retrieve all credentials for this user (optionally filtered by method)."""
        if getattr(self, "_credentials", None) and not not_cached:
            return self._credentials

        query = {
            "tenant_id": self.tenant_id,
            "user_id": self.uid,
            "is_deleted": False,
            "is_active": True,
            # Expiry is filtered in-memory below (null = never-expires).
            # Index on tenant_id+user_id+is_active covers lookup.
        }
        if method is not None:
            query["method"] = method

        def ensure_aware(dt: datetime) -> datetime:
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.tz)
            return dt

        creds: list[Credential] = await Credential.get_query(**query).to_list()
        self.credentials = [
            cred
            for cred in creds
            if cred.expires_at is None
            or ensure_aware(cred.expires_at) > datetime.now(timezone.tz)
        ]
        self._credentials = self.credentials
        return self.credentials

    async def get_profile(self) -> object | None:
        """Get profile for this user."""
        return await Profile.get_by_user_id(tenant_id=self.tenant_id, user_id=self.uid)

    async def get_last_used_credential(self) -> Credential | None:
        """Get last used credential for this user."""
        return await Credential.find_one({
            "tenant_id": self.tenant_id,
            "user_id": self.uid,
            "last_used_at": {"$ne": None},
        })

    async def get_last_activity(self) -> datetime | None:
        """Latest last_used_at across sessions, API keys, and agents."""
        timestamps: list[datetime] = []

        last_session = (
            await AuthSession
            .get_query(
                tenant_id=self.tenant_id,
                user_id=self.uid,
            )
            .sort("last_used_at", -1)
            .limit(1)
            .to_list()
        )
        if last_session and last_session[0].last_used_at:
            timestamps.append(last_session[0].last_used_at)

        last_api_key = (
            await APIKey
            .get_query(
                tenant_id=self.tenant_id,
                user_id=self.uid,
            )
            .sort("last_used_at", -1)
            .limit(1)
            .to_list()
        )
        if last_api_key and last_api_key[0].last_used_at:
            timestamps.append(last_api_key[0].last_used_at)

        last_agent = (
            await Agent
            .get_query(
                tenant_id=self.tenant_id,
                user_id=self.uid,
            )
            .sort("last_used_at", -1)
            .limit(1)
            .to_list()
        )
        if last_agent and last_agent[0].last_used_at:
            timestamps.append(last_agent[0].last_used_at)

        return max(timestamps) if timestamps else None

    @property
    def tenant(self) -> Tenant:
        """Tenant for this user."""
        return getattr(self, "_tenant", None)

    @tenant.setter
    def tenant(self, tenant: Tenant) -> None:
        self._tenant = tenant

    @property
    def current_identifier(self) -> UserIdentifier:
        """Current identifier for this user."""
        return getattr(self, "_current_identifier", None)

    @current_identifier.setter
    def current_identifier(self, identifier: UserIdentifier) -> None:
        self._current_identifier = identifier

    @property
    def credentials(self) -> list[Credential]:
        """Credentials for this user."""
        return getattr(self, "_credentials", [])

    @credentials.setter
    def credentials(self, credential: list[Credential]) -> None:
        self._credentials = credential

    async def activate(self) -> None:
        """Activate this user."""
        self.is_active = True
        await self.save()

    async def update_permissions_and_sessions(
        self,
        *,
        new_scopes: list[str] | None = None,
        user_scopes: list[str] | None = None,
        workspace_id: str | None = None,
    ) -> int:
        """
        Update user permissions and propagate changes to all active sessions.

        This method provides real-time permission updates across all user sessions.

        Args:
            new_scopes: New scopes to set (if None, will recalculate from roles)
            user_scopes: Scopes to use for API key/agent cap (if None, uses get_scopes)
            workspace_id: Specific workspace to update (optional)

        Returns:
            Number of sessions updated

        """
        if new_scopes is None:
            new_scopes = await self.get_scopes(workspace_id)
        if user_scopes is None:
            user_scopes = await self.get_scopes(workspace_id)

        new_roles = (
            (self.workspace_roles or {}).get(workspace_id) or []
            if workspace_id
            else (self.roles or [])
        )

        # Update all active sessions for this user
        updated_count = await AuthSession.update_user_sessions_permissions(
            user_id=self.uid,
            tenant_id=self.tenant_id,
            new_scopes=new_scopes,
            new_roles=new_roles,
            workspace_id=workspace_id,
        )

        await APIKey.cap_user_api_keys_scopes(
            user_id=self.uid,
            tenant_id=self.tenant_id,
            user_scopes=user_scopes or [],
            workspace_id=workspace_id,
        )
        await Agent.cap_user_agents_scopes(
            user_id=self.uid,
            tenant_id=self.tenant_id,
            user_scopes=user_scopes or [],
            workspace_id=workspace_id,
        )

        return updated_count

    async def to_detailed_schema(self) -> UserResponse:
        """Convert user to detailed schema."""
        item = UserResponse.model_validate(self)
        item.identifiers = await self.get_identifiers(not_cached=True)
        item.credential_methods = [cred.method for cred in await self.get_credentials()]
        return item

    @classmethod
    async def list_users_with_role(
        cls, *, tenant_id: str, role_name: str
    ) -> list[tuple[Self, list[str | None]]]:
        """
        Return users that have the given role, with workspace_id list per user.

        Each tuple is (user, workspace_ids): workspace_ids includes None for
        global role, and str for each workspace_roles key where role is present.
        Uses aggregation so only matching users are loaded from the DB.
        """
        pipeline = [
            {"$match": {"tenant_id": tenant_id, "is_deleted": False}},
            {
                "$addFields": {
                    "_workspace_ids_for_role": {
                        "$concatArrays": [
                            {
                                "$cond": [
                                    {
                                        "$in": [
                                            role_name,
                                            {"$ifNull": ["$roles", []]},
                                        ]
                                    },
                                    [None],
                                    [],
                                ]
                            },
                            {
                                "$map": {
                                    "input": {
                                        "$filter": {
                                            "input": {
                                                "$objectToArray": {
                                                    "$ifNull": [
                                                        "$workspace_roles",
                                                        {},
                                                    ]
                                                }
                                            },
                                            "as": "item",
                                            "cond": {
                                                "$in": [
                                                    role_name,
                                                    "$$item.v",
                                                ]
                                            },
                                        }
                                    },
                                    "as": "item",
                                    "in": "$$item.k",
                                }
                            },
                        ]
                    }
                }
            },
            {
                "$match": {
                    "$expr": {
                        "$gt": [
                            {"$size": "$_workspace_ids_for_role"},
                            0,
                        ]
                    }
                }
            },
        ]
        docs = await aggregate_to_list(cls, pipeline)
        result: list[tuple[Self, list[str | None]]] = []
        for doc in docs:
            workspace_ids = doc.pop("_workspace_ids_for_role", [])
            result.append((cls.model_validate(doc), workspace_ids))
        return result

    @classmethod
    async def propagate_role_scope_change(
        cls,
        *,
        tenant_id: str,
        role_name: str,
        role_workspace_id: str | None,
    ) -> None:
        """
        After a role's scopes change, update affected users' sessions and keys.

        One aggregation, one role load, then parallel updates.
        """
        users_with_workspaces = await cls.list_users_with_role(
            tenant_id=tenant_id, role_name=role_name
        )
        pairs: list[tuple[Self, str | None]] = [
            (user, ws)
            for user, workspace_ids in users_with_workspaces
            for ws in workspace_ids
            if role_workspace_id is None or ws == role_workspace_id
        ]
        if not pairs:
            return

        unique_workspace_ids = {ws for _, ws in pairs}
        workspace_id_in = [None] + [w for w in unique_workspace_ids if w is not None]
        all_roles = await Role.get_query(
            tenant_id=tenant_id, workspace_id_in=workspace_id_in
        ).to_list()

        def scopes_for(
            user: Self, workspace_id: str | None
        ) -> tuple[list[str], list[str]]:
            role_names = (
                (user.roles or [])
                if workspace_id is None
                else ((user.workspace_roles or {}).get(workspace_id) or [])
            )
            applicable = [
                r
                for r in all_roles
                if (r.workspace_id is None or r.workspace_id == workspace_id)
                and r.name in role_names
            ]
            scopes = list(set().union(*(set(r.scopes or []) for r in applicable)))
            return scopes, list(role_names)

        tasks = []
        for user, workspace_id in pairs:
            new_scopes, _ = scopes_for(user, workspace_id)
            tasks.append(
                user.update_permissions_and_sessions(
                    workspace_id=workspace_id,
                    new_scopes=new_scopes,
                    user_scopes=new_scopes,
                )
            )
        await asyncio.gather(*tasks)

    @classmethod
    async def delete_item(cls, item: Self) -> Self:
        """Soft-delete user plus identifiers, credentials, and sessions."""
        ui_delete = UserIdentifier.find({
            "user_id": item.uid,
            "is_deleted": False,
        }).update_many({"$set": {"is_deleted": True}})

        # Update all credentials
        c_delete = Credential.find({
            "user_id": item.uid,
            "is_deleted": False,
        }).update_many({"$set": {"is_deleted": True}})

        # Update all sessions
        s_delete = AuthSession.find({
            "user_id": item.uid,
            "is_deleted": False,
        }).update_many({"$set": {"is_deleted": True}})

        await asyncio.gather(ui_delete, c_delete, s_delete)
        return await super().delete_item(item)

    @classmethod
    async def hard_delete(cls, item: Self) -> Self:
        """
        Soft-delete a user and cascade belongings.

        Soft-deletes KYC, profile, API keys, agents, referral codes, and legal
        acceptances; soft-deletes workspaces where this user is the sole
        non-deleted member; then delegates to ``delete_item`` for identifiers,
        credentials, sessions, and the user row.
        """
        belonging_deletes = [
            KYC.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}}),
            Profile.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}}),
            APIKey.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}}),
            Agent.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}}),
            ReferralCode.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}}),
            LegalAcceptance.find({
                "user_id": item.uid,
                "is_deleted": False,
            }).update_many({"$set": {"is_deleted": True}}),
        ]
        await asyncio.gather(*belonging_deletes)

        for workspace_id in item.workspace_ids or []:
            member_count = await cls.total_count(
                tenant_id=item.tenant_id,
                workspace_ids_in=[workspace_id],
            )
            if member_count != 1:
                continue
            workspace = await Workspace.get_item(
                uid=workspace_id, tenant_id=item.tenant_id
            )
            if workspace is not None:
                await Workspace.delete_item(workspace)

        return await cls.delete_item(item)

    @classmethod
    async def total_count(
        cls,
        *,
        uid: str | None = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        offset: int = 0,
        limit: int | None = None,
        sort_field: str = "created_at",
        sort_direction: int = -1,
        is_deleted: bool = False,
        role: str | None = None,
        identifier_type: AuthIdentifier | None = None,
        identifier: str | None = None,
        **kwargs: object,
    ) -> int:
        """Get total count of users."""
        if identifier_type is None and identifier is None:
            return await super().total_count(
                uid=uid,
                user_id=user_id,
                tenant_id=tenant_id,
                offset=offset,
                limit=limit,
                sort_field=sort_field,
                sort_direction=sort_direction,
                is_deleted=is_deleted,
                roles_in=role,
                **kwargs,
            )
        return await cls._total_count_with_identifier_filter(
            uid=uid,
            user_id=user_id,
            tenant_id=tenant_id,
            offset=offset,
            limit=limit,
            sort_field=sort_field,
            sort_direction=sort_direction,
            is_deleted=is_deleted,
            role=role,
            identifier_type=identifier_type,
            identifier=identifier,
            **kwargs,
        )

    @classmethod
    async def list_items(
        cls,
        *,
        uid: str | None = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        offset: int = 0,
        limit: int | None = None,
        sort_field: str = "created_at",
        sort_direction: int = -1,
        is_deleted: bool = False,
        role: str | None = None,
        identifier_type: AuthIdentifier | None = None,
        identifier: str | None = None,
        **kwargs: object,
    ) -> list[Self]:
        """List users with filtering and pagination."""
        # If we need to filter by identifier, use aggregation pipeline

        if user_id and not uid:
            uid = user_id

        if identifier_type is None and identifier is None:
            return await super().list_items(
                uid=uid,
                tenant_id=tenant_id,
                offset=offset,
                limit=limit,
                sort_field=sort_field,
                sort_direction=sort_direction,
                is_deleted=is_deleted,
                roles_in=role,
                **kwargs,
            )

        return await cls._list_items_with_identifier_filter(
            uid=uid,
            tenant_id=tenant_id,
            offset=offset,
            limit=limit,
            sort_field=sort_field,
            sort_direction=sort_direction,
            is_deleted=is_deleted,
            role=role,
            identifier_type=identifier_type,
            identifier=identifier,
            **kwargs,
        )

    @classmethod
    async def _list_items_with_identifier_filter(
        cls,
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
        offset: int = 0,
        limit: int | None = None,
        sort_field: str = "created_at",
        sort_direction: int = -1,
        is_deleted: bool = False,
        role: str | None = None,
        identifier_type: AuthIdentifier | None = None,
        identifier: str | None = None,
        **kwargs: object,
    ) -> list[Self]:
        """List items with identifier filtering using aggregation pipeline."""
        # Build the base match stage from queryset filters
        base_query = cls.get_queryset(
            user_id=user_id,
            tenant_id=tenant_id,
            is_deleted=is_deleted,
            roles_in=role,
            **kwargs,
        )

        # Build identifier match conditions
        identifier_match = {}
        if identifier_type is not None or identifier is not None:
            elem_match_conditions = {}
            if identifier_type is not None:
                elem_match_conditions["type"] = identifier_type
            if identifier is not None:
                # Use regex for partial matching (case-insensitive)
                elem_match_conditions["identifier"] = {
                    "$regex": _normalize_identifier_search(identifier),
                    "$options": "i",
                }
            identifier_match["identifiers"] = {"$elemMatch": elem_match_conditions}

        # Build aggregation pipeline
        pipeline = [
            # Match base filters first
            {"$match": base_query},
            # Lookup UserIdentifier documents
            {
                "$lookup": {
                    "from": "UserIdentifier",  # Collection name for UserIdentifier
                    "let": {"user_id": "$uid", "user_tenant_id": "$tenant_id"},
                    "pipeline": [
                        {
                            "$match": {
                                "$expr": {
                                    "$and": [
                                        {"$eq": ["$user_id", "$$user_id"]},
                                        {"$eq": ["$tenant_id", "$$user_tenant_id"]},
                                        {"$eq": ["$is_deleted", False]},
                                    ]
                                }
                            }
                        }
                    ],
                    "as": "identifiers",
                }
            },
            # Match users that have matching identifiers
            {"$match": identifier_match} if identifier_match else {"$match": {}},
            # Sort the results
            {"$sort": {sort_field: sort_direction}},
            # Apply pagination
            {"$skip": offset},
        ]

        # Add limit if specified
        if limit:
            pipeline.append({"$limit": limit})

        # Execute aggregation
        items = await aggregate_to_list(cls, pipeline)

        # Convert to model instances
        return [cls.model_validate(item) for item in items]

    @classmethod
    async def _total_count_with_identifier_filter(
        cls,
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
        offset: int = 0,
        limit: int | None = None,
        sort_field: str = "created_at",
        sort_direction: int = -1,
        is_deleted: bool = False,
        role: str | None = None,
        identifier_type: AuthIdentifier | None = None,
        identifier: str | None = None,
        **kwargs: object,
    ) -> int:
        base_query = cls.get_queryset(
            user_id=user_id,
            tenant_id=tenant_id,
            is_deleted=is_deleted,
            roles_in=role,
            **kwargs,
        )
        # Build identifier match conditions
        identifier_match = {}
        if identifier_type is not None or identifier is not None:
            elem_match_conditions = {}
            if identifier_type is not None:
                elem_match_conditions["type"] = identifier_type
            if identifier is not None:
                # Use regex for partial matching (case-insensitive)
                elem_match_conditions["identifier"] = {
                    "$regex": identifier,
                    "$options": "i",
                }
            identifier_match["identifiers"] = {"$elemMatch": elem_match_conditions}

        # Build aggregation pipeline
        pipeline = [
            # Match base filters first
            {"$match": base_query},
            # Lookup UserIdentifier documents
            {
                "$lookup": {
                    "from": "UserIdentifier",  # Collection name for UserIdentifier
                    "let": {"user_id": "$uid", "user_tenant_id": "$tenant_id"},
                    "pipeline": [
                        {
                            "$match": {
                                "$expr": {
                                    "$and": [
                                        {"$eq": ["$user_id", "$$user_id"]},
                                        {"$eq": ["$tenant_id", "$$user_tenant_id"]},
                                        {"$eq": ["$is_deleted", False]},
                                    ]
                                }
                            }
                        }
                    ],
                    "as": "identifiers",
                }
            },
            # Match users that have matching identifiers
            {"$match": identifier_match} if identifier_match else {"$match": {}},
            # Sort the results
            {"$sort": {sort_field: sort_direction}},
            {"$count": "total"},
        ]
        result = await aggregate_to_list(cls, pipeline, length=1)
        if not result:
            return 0
        return result[0].get("total", 0)

    @classmethod
    async def list_total_combined(
        cls,
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
        offset: int = 0,
        limit: int = 10,
        is_deleted: bool = False,
        role: str | None = None,
        identifier_type: AuthIdentifier | None = None,
        identifier: str | None = None,
        sort_field: str = "created_at",
        sort_direction: int = -1,
        **kwargs: object,
    ) -> tuple[list[Self], int]:
        """Return a page, identifiers and total using one Mongo aggregation."""
        if user_id and not kwargs.get("uid"):
            kwargs["uid"] = user_id
        base_query = cls.get_queryset(
            tenant_id=tenant_id,
            is_deleted=is_deleted,
            roles_in=role,
            **kwargs,
        )
        identifier_conditions: dict[str, object] = {}
        if identifier_type is not None:
            identifier_conditions["type"] = identifier_type
        if identifier is not None:
            identifier_conditions["identifier"] = {
                "$regex": _normalize_identifier_search(identifier),
                "$options": "i",
            }

        pipeline: list[dict[str, object]] = [
            {"$match": base_query},
            {
                "$lookup": {
                    "from": "UserIdentifier",
                    "let": {"user_id": "$uid", "user_tenant_id": "$tenant_id"},
                    "pipeline": [
                        {
                            "$match": {
                                "$expr": {
                                    "$and": [
                                        {"$eq": ["$user_id", "$$user_id"]},
                                        {"$eq": ["$tenant_id", "$$user_tenant_id"]},
                                        {"$eq": ["$is_deleted", False]},
                                    ],
                                },
                            },
                        },
                    ],
                    "as": "identifiers",
                },
            },
        ]
        if identifier_conditions:
            pipeline.append({
                "$match": {"identifiers": {"$elemMatch": identifier_conditions}},
            })
        pipeline.append({
            "$facet": {
                "items": [
                    {"$sort": {sort_field: sort_direction}},
                    {"$skip": offset},
                    {"$limit": limit},
                ],
                "metadata": [{"$count": "total"}],
            },
        })

        result = await aggregate_to_list(cls, pipeline, length=1)
        page = result[0] if result else {"items": [], "metadata": []}
        # Return response models so the joined identifiers survive the generic
        # router's model_dump -> list schema conversion without being stored on User.
        items = [UserResponse.model_validate(item) for item in page.get("items", [])]
        metadata = page.get("metadata", [])
        total = int(metadata[0]["total"]) if metadata else 0
        return items, total
