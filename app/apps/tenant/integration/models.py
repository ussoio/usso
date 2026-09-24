"""
OAuth2/OIDC models for tenant integration.

This module contains database models for OAuth2 and OpenID Connect
authorization server functionality.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import ClassVar, Self

from fastapi_mongo_base.models import ASCENDING, IndexModel, TenantUserEntity
from fastapi_mongo_base.utils import timezone
from pydantic import Field, PrivateAttr

from .schemas import (
    OAuthClientSchema,
    OuathDeviceAuthorizationStatus,
    TokenType,
)


class OAuthClient(OAuthClientSchema, TenantUserEntity):
    """OAuth2 Client model."""

    registration_access_token: str | None = Field(
        default=None,
        description="Registration access token",
    )

    class Settings:
        """Settings for the OAuth client model."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel([("client_id", ASCENDING)], unique=True),
            IndexModel([("tenant_id", ASCENDING)]),
            IndexModel([("is_active", ASCENDING)]),
        ]

    @classmethod
    async def get_by_client_id(cls, client_id: str, tenant_id: str) -> Self | None:
        """Get OAuth client by client ID and tenant ID."""
        return await cls.find_one(
            {"client_id": client_id, "tenant_id": tenant_id, "is_active": True},
        )

    @classmethod
    def generate_client_id(cls) -> str:
        """Generate a unique client ID."""
        return f"uc_{secrets.token_urlsafe(16)}"

    @classmethod
    def generate_client_secret(cls) -> str:
        """Generate a client secret."""
        return secrets.token_urlsafe(32)


class AuthorizationCode(TenantUserEntity):
    """OAuth2 Authorization Code model."""

    code: str = Field(..., description="Authorization code")
    client_id: str = Field(..., description="Client ID")
    redirect_uri: str = Field(..., description="Redirect URI")
    scope: list[str] = Field(..., description="Granted scopes")
    nonce: str | None = Field(None, description="Nonce for ID token")
    code_challenge: str | None = Field(None, description="PKCE code challenge")
    code_challenge_method: str | None = Field(
        None, description="PKCE code challenge method"
    )
    expires_at: datetime = Field(..., description="Code expiration time")
    is_used: bool = Field(default=False, description="Whether the code has been used")

    class Settings:
        """Settings for the OAuth authorization code model."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel([("code", ASCENDING)], unique=True),
            IndexModel([("client_id", ASCENDING)]),
            IndexModel([("expires_at", ASCENDING)]),
            IndexModel([("is_used", ASCENDING)]),
        ]

    @classmethod
    async def get_by_code(cls, code: str, tenant_id: str) -> Self | None:
        """Get authorization code by code and tenant ID."""
        return await cls.find_one({
            "code": code,
            "tenant_id": tenant_id,
            "is_used": False,
            "expires_at": {"$gt": datetime.now(timezone.tz)},
        })

    @classmethod
    def generate_code(cls) -> str:
        """Generate a unique authorization code."""
        return secrets.token_urlsafe(32)

    @classmethod
    def create_code(
        cls,
        client_id: str,
        user_id: str,
        tenant_id: str,
        redirect_uri: str,
        scope: list[str],
        nonce: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        expires_in: int = 600,  # 10 minutes
    ) -> Self:
        """Create a new authorization code."""
        return cls(
            code=cls.generate_code(),
            client_id=client_id,
            user_id=user_id,
            tenant_id=tenant_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=datetime.now(timezone.tz) + timedelta(seconds=expires_in),
        )

    def is_expired(self) -> bool:
        """Check if the authorization code is expired."""
        return datetime.now(timezone.tz) > self.expires_at


class OAuthToken(TenantUserEntity):
    """OAuth2 Token model."""

    token: str = Field(..., description="Token value")
    token_type: TokenType = Field(..., description="Token type")
    client_id: str = Field(..., description="Client ID")
    scope: list[str] = Field(..., description="Token scopes")
    expires_at: datetime = Field(..., description="Token expiration time")
    is_revoked: bool = Field(default=False, description="Whether the token is revoked")

    # For refresh tokens
    refresh_token: str | None = Field(None, description="Associated refresh token")
    parent_token_id: str | None = Field(
        None, description="Parent token ID (for refresh tokens)"
    )

    # For access tokens
    access_token_id: str | None = Field(None, description="Associated access token ID")
    _raw_token: str | None = PrivateAttr(default=None)

    class Settings:
        """Settings for the OAuth token model."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel([("token", ASCENDING)], unique=True),
            IndexModel([("client_id", ASCENDING)]),
            IndexModel([("token_type", ASCENDING)]),
            IndexModel([("expires_at", ASCENDING)]),
            IndexModel([("is_revoked", ASCENDING)]),
            IndexModel([("refresh_token", ASCENDING)]),
        ]

    @classmethod
    async def get_by_token(cls, token: str, tenant_id: str) -> Self | None:
        """Get token by token value and tenant ID."""
        return await cls.find_one({
            "token": hashlib.sha256(token.encode()).hexdigest(),
            "tenant_id": tenant_id,
            "is_revoked": False,
            "expires_at": {"$gt": datetime.now(timezone.tz)},
        })

    @classmethod
    async def get_by_refresh_token(
        cls, refresh_token: str, tenant_id: str
    ) -> Self | None:
        """Get token by refresh token and tenant ID."""
        return await cls.find_one({
            "refresh_token": hashlib.sha256(refresh_token.encode()).hexdigest(),
            "tenant_id": tenant_id,
            "is_revoked": False,
            "expires_at": {"$gt": datetime.now(timezone.tz)},
        })

    @classmethod
    def generate_token(cls) -> str:
        """Generate a unique token."""
        return secrets.token_urlsafe(48)

    @classmethod
    def create_access_token(
        cls,
        client_id: str,
        user_id: str,
        tenant_id: str,
        scope: list[str],
        expires_in: int = 3600,  # 1 hour
    ) -> Self:
        """Create a new access token."""
        raw_token = cls.generate_token()
        item = cls(
            token=hashlib.sha256(raw_token.encode()).hexdigest(),
            token_type=TokenType.BEARER,
            client_id=client_id,
            user_id=user_id,
            tenant_id=tenant_id,
            scope=scope,
            expires_at=datetime.now(timezone.tz) + timedelta(seconds=expires_in),
        )
        item._raw_token = raw_token
        return item

    @classmethod
    def create_refresh_token(
        cls,
        client_id: str,
        user_id: str,
        tenant_id: str,
        scope: list[str],
        access_token_id: str,
        expires_in: int = 86400 * 30,  # 30 days
    ) -> Self:
        """Create a new refresh token."""
        refresh_token_value = cls.generate_token()
        digest = hashlib.sha256(refresh_token_value.encode()).hexdigest()
        item = cls(
            token=digest,
            token_type=TokenType.BEARER,
            client_id=client_id,
            user_id=user_id,
            tenant_id=tenant_id,
            scope=scope,
            refresh_token=digest,
            access_token_id=access_token_id,
            expires_at=datetime.now(timezone.tz) + timedelta(seconds=expires_in),
        )
        item._raw_token = refresh_token_value
        return item

    @property
    def raw_token(self) -> str:
        """Newly generated plaintext, available once before it leaves memory."""
        if self._raw_token is None:
            raise RuntimeError("Plaintext token is not available")
        return self._raw_token

    def is_expired(self) -> bool:
        """Check if the token is expired."""
        return datetime.now(timezone.tz) > self.expires_at

    async def revoke(self) -> None:
        """Revoke the token."""
        self.is_revoked = True
        await self.save()

    async def revoke_related_tokens(self) -> None:
        """Revoke related tokens (access/refresh token pairs)."""
        if self.access_token_id:
            # This is a refresh token, revoke the access token
            access_token = await OAuthToken.find_one({
                "uid": self.access_token_id,
                "tenant_id": self.tenant_id,
                "is_deleted": False,
            })
            if access_token:
                await access_token.revoke()
        elif self.refresh_token:
            # This is an access token, revoke the refresh token
            refresh_token = await OAuthToken.find_one({
                "refresh_token": self.refresh_token,
                "tenant_id": self.tenant_id,
                "is_revoked": False,
            })
            if refresh_token:
                await refresh_token.revoke()

        await self.revoke()


class OAuthSession(TenantUserEntity):
    """OAuth2 Session model for tracking user consent and state."""

    client_id: str = Field(..., description="Client ID")
    state: str | None = Field(None, description="State parameter")
    nonce: str | None = Field(None, description="Nonce parameter")
    code_challenge: str | None = Field(None, description="PKCE challenge")
    code_challenge_method: str | None = Field(None, description="PKCE method")
    scope: list[str] = Field(..., description="Requested scopes")
    redirect_uri: str = Field(..., description="Redirect URI")
    granted_scope: list[str] = Field(default_factory=list, description="Granted scopes")
    is_consented: bool = Field(default=False, description="Whether user has consented")
    is_consumed: bool = Field(
        default=False,
        description="Whether the consent decision has already been finalized",
    )
    expires_at: datetime = Field(..., description="Session expiration time")

    class Settings:
        """Settings for the OAuth session model."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel([("client_id", ASCENDING)]),
            IndexModel([("state", ASCENDING)]),
            IndexModel([("expires_at", ASCENDING)]),
        ]

    @classmethod
    async def get_by_state(cls, state: str, tenant_id: str) -> Self | None:
        """Get session by state and tenant ID."""
        return await cls.find_one({
            "state": state,
            "tenant_id": tenant_id,
            "expires_at": {"$gt": datetime.now(timezone.tz)},
        })

    @classmethod
    def create_session(
        cls,
        client_id: str,
        user_id: str,
        tenant_id: str,
        scope: list[str],
        redirect_uri: str,
        state: str | None = None,
        nonce: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        expires_in: int = 3600,  # 1 hour
    ) -> Self:
        """Create a new OAuth session."""
        return cls(
            client_id=client_id,
            user_id=user_id,
            tenant_id=tenant_id,
            scope=scope,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=datetime.now(timezone.tz) + timedelta(seconds=expires_in),
        )

    def is_expired(self) -> bool:
        """Check if the session is expired."""
        return datetime.now(timezone.tz) > self.expires_at.replace(tzinfo=timezone.tz)

    def grant_consent(self, granted_scope: list[str]) -> None:
        """Grant user consent for the requested scopes."""
        self.is_consented = True
        self.granted_scope = granted_scope


class OuathDeviceAuthorization(TenantUserEntity):
    """RFC 8628 device authorization request (pending user approval)."""

    client_id: str = Field(..., description="OAuth client ID")
    device_code: str = Field(..., description="High-entropy device code")
    user_code: str = Field(..., description="User-facing code (XXXX-XXXX)")
    user_code_normalized: str = Field(
        ..., description="Normalized user code for lookup"
    )
    scope: list[str] = Field(default_factory=list, description="Requested scopes")
    granted_scope: list[str] = Field(
        default_factory=list, description="Scopes granted after approval"
    )
    status: OuathDeviceAuthorizationStatus = Field(
        default=OuathDeviceAuthorizationStatus.PENDING,
        description="Authorization status",
    )
    authorized_user_id: str | None = Field(
        None, description="User who approved or denied the request"
    )
    interval: int = Field(default=5, description="Minimum polling interval seconds")
    last_polled_at: datetime | None = Field(
        None, description="Last token-endpoint poll time"
    )
    expires_at: datetime = Field(..., description="Expiration time")
    is_consumed: bool = Field(
        default=False, description="Whether tokens were already issued"
    )

    class Settings:
        """Indexes for device authorization lookup and expiry."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel([("device_code", ASCENDING)], unique=True),
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("user_code_normalized", ASCENDING),
                    ("status", ASCENDING),
                ],
            ),
            IndexModel([("expires_at", ASCENDING)]),
            IndexModel([("client_id", ASCENDING)]),
        ]

    def is_expired(self) -> bool:
        """Check if the device authorization has expired."""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.tz)
        return datetime.now(timezone.tz) > expires_at
