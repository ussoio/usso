"""Unit tests for service-account subject binding and API key identity."""

from datetime import datetime
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi_mongo_base.utils import timezone
from pydantic import ValidationError

from apps.identity import service_account as sa
from apps.identity.api_key import services as api_key_services
from apps.identity.api_key.schemas import APIKeySchema
from apps.tenant.integration import services as oauth_services
from server.exceptions import BadRequestError, ForbiddenError, UnauthorizedError


def _caller(
    *,
    uid: str = "u1",
    workspace_id: str | None = "ws-1",
    scopes: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        uid=uid,
        user_id=uid,
        workspace_id=workspace_id,
        scopes=scopes or [],
    )


def test_resolve_create_binding_defaults_both_from_jwt() -> None:
    """Omitted binding prefers caller's user_id + workspace_id."""
    user_id, workspace_id = sa.resolve_create_binding(
        caller=_caller(),
        user_id=None,
        workspace_id=None,
    )
    assert user_id == "u1"
    assert workspace_id == "ws-1"


def test_resolve_create_binding_user_only_when_no_workspace() -> None:
    """Without JWT workspace, default is user-only."""
    user_id, workspace_id = sa.resolve_create_binding(
        caller=_caller(workspace_id=None),
        user_id=None,
        workspace_id=None,
    )
    assert user_id == "u1"
    assert workspace_id is None


def test_api_key_schema_requires_subject() -> None:
    """Persisted API key must bind to user and/or workspace."""
    with pytest.raises(ValidationError):
        APIKeySchema(
            api_key_pattern="uak-****",
            hashed_key="x",
            tenant_id="t1",
        )


def test_authorize_workspace_only_requires_manage() -> None:
    """Workspace-only create without manage is denied."""
    with pytest.raises(ForbiddenError) as exc:
        sa.authorize_service_account_create(
            caller=_caller(scopes=["read:sso/*/*?workspace_id=ws-1"]),
            user_id=None,
            workspace_id="ws-1",
        )
    assert exc.value.error_code == "workspace_manage_denied"


def test_authorize_self_in_workspace_without_manage() -> None:
    """Self-service user+workspace create is allowed without manage."""
    sa.authorize_service_account_create(
        caller=_caller(scopes=["read:sso/*/*?workspace_id=ws-1"]),
        user_id="u1",
        workspace_id="ws-1",
    )


def test_api_key_user_data_sub_is_key_uid() -> None:
    """API key principal identity is the key uid, not the owner user."""
    db_key = SimpleNamespace(
        uid="key-1",
        tenant_id="t1",
        workspace_id="ws-1",
        user_id="u1",
        created_by="u1",
        scopes=["read:r"],
        created_at=datetime.now(timezone.tz),
    )
    data = api_key_services.api_key_to_user_data(db_key)  # type: ignore[arg-type]
    assert data.sub == "key-1"
    assert data.workspace_id == "ws-1"
    assert data.user_id == "u1"
    assert data.amr == ["api_key"]


@pytest.mark.asyncio
async def test_client_credentials_rejects_bad_secret() -> None:
    """Wrong client_secret is rejected."""
    secret_hash = "stored-hash"
    db_key = SimpleNamespace(
        uid="key-1",
        tenant_id="t1",
        hashed_client_secret=secret_hash,
        is_active=True,
        revoked=None,
        expires_at=None,
        scopes=["read:r"],
        workspace_id="ws-1",
        user_id="u1",
        created_by="u1",
    )
    tenant = SimpleNamespace(uid="t1")
    bad_secret = "wrong-secret"

    with (
        mock.patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=mock.AsyncMock(return_value=db_key),
        ),
        mock.patch(
            "apps.identity.api_key.services.verify_client_secret",
            return_value=False,
        ),
        pytest.raises(UnauthorizedError) as exc,
    ):
        await oauth_services.exchange_service_account_client_credentials(
            tenant=tenant,  # type: ignore[arg-type]
            client_id="key-1",
            client_secret=bad_secret,
            scope=None,
        )
    assert exc.value.error_code == "invalid_client"


@pytest.mark.asyncio
async def test_client_credentials_issues_token() -> None:
    """Valid client_secret returns a bearer access token."""
    secret_hash = "stored-hash"
    plain_secret = "client-secret"
    db_key = SimpleNamespace(
        uid="key-1",
        tenant_id="t1",
        hashed_client_secret=secret_hash,
        is_active=True,
        revoked=None,
        expires_at=None,
        scopes=["read:r", "create:r"],
        workspace_id="ws-1",
        user_id="u1",
        created_by="u1",
        ip_whitelist=[],
        rate_limit={},
    )
    tenant = SimpleNamespace(
        uid="t1",
        primary_url="https://example.test",
        config=SimpleNamespace(
            token=SimpleNamespace(access_timeout=3600),
        ),
        sign_jwt=mock.Mock(return_value="signed.jwt"),
    )

    with (
        mock.patch(
            "apps.identity.api_key.models.APIKey.find_one",
            new=mock.AsyncMock(return_value=db_key),
        ),
        mock.patch(
            "apps.identity.api_key.services.verify_client_secret",
            return_value=True,
        ),
        mock.patch(
            "apps.identity.api_key.services._validate_api_key_state",
        ),
    ):
        result = await oauth_services.exchange_service_account_client_credentials(
            tenant=tenant,  # type: ignore[arg-type]
            client_id="key-1",
            client_secret=plain_secret,
            scope="read:r",
        )

    assert result.access_token == "signed.jwt"
    assert result.refresh_token is None
    assert result.scope == "read:r"
    payload = tenant.sign_jwt.call_args.args[0]
    assert payload["sub"] == "key-1"
    assert payload["workspace_id"] == "ws-1"
    assert payload["user_id"] == "u1"
    assert payload["amr"] == ["client_credentials"]


def test_assert_scopes_subset_denies_extra() -> None:
    """Requested scopes must be covered by the ceiling."""
    with pytest.raises(ForbiddenError) as exc:
        sa.assert_scopes_subset(
            requested=["manage:r"],
            ceiling=["read:r"],
        )
    assert exc.value.error_code == "invalid_scopes"


def test_resolve_create_binding_requires_subject() -> None:
    """Empty caller and empty binding is rejected."""
    with pytest.raises(BadRequestError) as exc:
        sa.resolve_create_binding(
            caller=_caller(uid="", workspace_id=None),
            user_id=None,
            workspace_id=None,
        )
    assert exc.value.error_code == "subject_required"


def test_subject_mixin_and_other_user_authorization_guards() -> None:
    with pytest.raises(ValidationError):
        sa.SubjectBindingMixin()
    with pytest.raises(ForbiddenError) as denied:
        sa.authorize_service_account_create(
            caller=_caller(), user_id="other", workspace_id=None
        )
    assert denied.value.error_code == "user_manage_denied"


@pytest.mark.asyncio
async def test_scope_ceiling_missing_target_and_caller_fallback() -> None:
    caller_user = SimpleNamespace(
        tenant_id="tenant",
        get_effective_scopes_for_api=mock.AsyncMock(return_value=["read:x"]),
    )
    with (
        mock.patch(
            "apps.identity.service_account.User.get_item",
            new=mock.AsyncMock(return_value=None),
        ),
        pytest.raises(BadRequestError) as missing,
    ):
        await sa.resolve_scope_ceiling(
            caller_user=caller_user,
            user_id="missing",
            workspace_id=None,
        )
    assert missing.value.error_code == "user_not_found"

    assert await sa.resolve_scope_ceiling(
        caller_user=caller_user,
        user_id=None,
        workspace_id="workspace",
    ) == ["read:x"]
