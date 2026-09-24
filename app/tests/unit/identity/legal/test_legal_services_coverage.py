"""Focused branch coverage for asynchronous legal services."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_mongo_base.utils import timezone

from apps.identity.legal import services
from apps.identity.legal.schemas import (
    LegalAcceptanceCreateSchema,
    LegalAcceptanceSchema,
    LegalAcceptanceSource,
    LegalDocumentCreateSchema,
    LegalDocumentType,
    LegalSubjectScope,
)
from server.exceptions import (
    BadRequestError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
)


def _document_dict(*, acceptance: object = None) -> dict:
    return {
        "uid": "doc-1",
        "tenant_id": "tenant-1",
        "document_type": LegalDocumentType.TERMS,
        "subject_scope": LegalSubjectScope.USER,
        "version": "v1",
        "title": "Terms",
        "content": "Legal text",
        "is_active": True,
        "acceptance": acceptance,
    }


def _acceptance_schema(*, workspace_id: str | None = None) -> LegalAcceptanceSchema:
    return LegalAcceptanceSchema(
        uid="accept-1",
        tenant_id="tenant-1",
        user_id="user-1",
        document_id="doc-1",
        workspace_id=workspace_id,
        source=LegalAcceptanceSource.LOGIN,
        subject_scope=(
            LegalSubjectScope.WORKSPACE if workspace_id else LegalSubjectScope.USER
        ),
        document_type=LegalDocumentType.TERMS,
        document_version="v1",
        document_content_hash="hash",
        accepted_at=datetime.now(timezone.tz),
        ip_address="127.0.0.1",
        user_agent="pytest",
    )


@pytest.mark.asyncio
async def test_authorize_workspace_document_signing_requires_workspace() -> None:
    with pytest.raises(BadRequestError) as exc:
        await services.authorize_workspace_document_signing(
            tenant_id="tenant-1", user_id="user-1", workspace_id=None
        )
    assert exc.value.error_code == "workspace_required"


@pytest.mark.asyncio
async def test_authorize_workspace_document_signing_user_and_membership_errors() -> (
    None
):
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=None)),
        pytest.raises(NotFoundError),
    ):
        await services.authorize_workspace_document_signing(
            tenant_id="tenant-1", user_id="user-1", workspace_id="ws-1"
        )

    outsider = SimpleNamespace(workspace_ids=[], roles=[])
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=outsider)),
        pytest.raises(ForbiddenError, match="not a member"),
    ):
        await services.authorize_workspace_document_signing(
            tenant_id="tenant-1", user_id="user-1", workspace_id="ws-1"
        )


@pytest.mark.asyncio
async def test_authorize_workspace_document_signing_admin_shortcut() -> None:
    admin = SimpleNamespace(workspace_ids=["ws-1"], roles=["admin"])
    with patch.object(services.User, "get_item", new=AsyncMock(return_value=admin)):
        result = await services.authorize_workspace_document_signing(
            tenant_id="tenant-1", user_id="user-1", workspace_id="ws-1"
        )
    assert result is admin


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [True, False])
async def test_authorize_workspace_document_signing_scope(allowed: bool) -> None:
    user = SimpleNamespace(
        workspace_ids=["ws-1"], roles=[], get_scopes=AsyncMock(return_value=["scope"])
    )
    with (
        patch.object(services.User, "get_item", new=AsyncMock(return_value=user)),
        patch.object(
            services.authorization, "has_subset_scope", return_value=allowed
        ) as has,
    ):
        if allowed:
            assert (
                await services.authorize_workspace_document_signing(
                    tenant_id="tenant-1", user_id="user-1", workspace_id="ws-1"
                )
                is user
            )
        else:
            with pytest.raises(ForbiddenError, match="not allowed"):
                await services.authorize_workspace_document_signing(
                    tenant_id="tenant-1", user_id="user-1", workspace_id="ws-1"
                )
    has.assert_called_once_with(
        user_scopes=["scope"],
        subset_scope="create:sso/legal-acceptance?workspace_id=ws-1",
    )


def test_authorize_user_sign_workspace_document_errors_and_allow() -> None:
    wrong_tenant = SimpleNamespace(tenant_id="other", scopes=[])
    with pytest.raises(UnauthorizedError):
        services.authorize_user_sign_workspace_document(
            tenant_id="tenant-1", user=wrong_tenant, workspace_id="ws-1"
        )

    user = SimpleNamespace(tenant_id="tenant-1", scopes=["scope"])
    with patch.object(services.authorization, "has_subset_scope", return_value=True):
        assert (
            services.authorize_user_sign_workspace_document(
                tenant_id="tenant-1", user=user, workspace_id="ws-1"
            )
            is user
        )
    with (
        patch.object(services.authorization, "has_subset_scope", return_value=False),
        pytest.raises(ForbiddenError),
    ):
        services.authorize_user_sign_workspace_document(
            tenant_id="tenant-1", user=user, workspace_id="ws-1"
        )


def _publish_payload(*, active: bool) -> LegalDocumentCreateSchema:
    return LegalDocumentCreateSchema(
        document_type=LegalDocumentType.TERMS,
        subject_scope=LegalSubjectScope.USER,
        version="v1",
        title="Terms",
        content="Legal text",
        is_active=active,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [True, False])
async def test_publish_document_deactivates_only_for_active_payload(
    active: bool,
) -> None:
    saved = MagicMock(name="saved-document")
    instance = MagicMock()
    instance.save = AsyncMock(return_value=saved)
    document_cls = MagicMock(return_value=instance)
    update_many = AsyncMock()
    document_cls.find.return_value.update_many = update_many
    with patch.object(services, "LegalDocument", document_cls):
        assert (
            await services.publish_document(
                tenant_id="tenant-1", payload=_publish_payload(active=active)
            )
            is saved
        )
    if active:
        update_many.assert_awaited_once_with({"$set": {"is_active": False}})
    else:
        update_many.assert_not_awaited()
    assert document_cls.call_args.kwargs["tenant_id"] == "tenant-1"


@pytest.mark.asyncio
async def test_get_public_active_documents_maps_documents() -> None:
    await services.get_public_active_documents.cache.clear()
    get_active = AsyncMock(return_value=[_document_dict()])
    with patch.object(services.LegalDocument, "get_active_documents", new=get_active):
        result = await services.get_public_active_documents(
            tenant_id="tenant-public",
            offset=2,
            limit=5,
            subject_scope=LegalSubjectScope.USER,
            document_type=LegalDocumentType.TERMS,
        )
    assert result[0].uid == "doc-1"
    get_active.assert_awaited_once_with(
        tenant_id="tenant-public",
        offset=2,
        limit=5,
        subject_scope=LegalSubjectScope.USER,
        document_type=LegalDocumentType.TERMS,
    )
    await services.get_public_active_documents.cache.clear()


def _document(scope: LegalSubjectScope) -> SimpleNamespace:
    return SimpleNamespace(
        uid="doc-1",
        is_active=True,
        subject_scope=scope,
        document_type=LegalDocumentType.TERMS,
        version="v1",
        content_hash="hash",
    )


def _accept_payload(workspace_id: str | None = None) -> LegalAcceptanceCreateSchema:
    return LegalAcceptanceCreateSchema(document_id="doc-1", workspace_id=workspace_id)


@pytest.mark.asyncio
async def test_accept_document_rejects_missing_or_inactive_document() -> None:
    for document in (None, SimpleNamespace(is_active=False)):
        with (
            patch.object(
                services.LegalDocument, "get_item", new=AsyncMock(return_value=document)
            ),
            pytest.raises(NotFoundError),
        ):
            await services.accept_document(
                tenant_id="tenant-1",
                user=SimpleNamespace(uid="user-1"),
                payload=_accept_payload(),
                ip_address="127.0.0.1",
                user_agent="pytest",
            )


@pytest.mark.asyncio
async def test_accept_user_document_existing_short_circuit() -> None:
    existing = _acceptance_schema()
    find = AsyncMock(return_value=existing)
    with (
        patch.object(
            services.LegalDocument,
            "get_item",
            new=AsyncMock(return_value=_document(LegalSubjectScope.USER)),
        ),
        patch.object(services.LegalAcceptance, "find_for_document", new=find),
    ):
        result = await services.accept_document(
            tenant_id="tenant-1",
            user=SimpleNamespace(uid="user-1"),
            payload=_accept_payload(),
            ip_address="127.0.0.1",
            user_agent="pytest",
        )
    assert result.uid == "accept-1"
    assert find.await_args.kwargs["user_id"] == "user-1"


@pytest.mark.asyncio
async def test_accept_workspace_document_authorizes_and_saves_new() -> None:
    saved = _acceptance_schema(workspace_id="ws-1")
    instance = MagicMock()
    instance.save = AsyncMock(return_value=saved)
    acceptance_cls = MagicMock(return_value=instance)
    acceptance_cls.find_for_document = AsyncMock(return_value=None)
    authorize = MagicMock()
    user = SimpleNamespace(uid="user-1", workspace_id="ws-fallback")
    with (
        patch.object(
            services.LegalDocument,
            "get_item",
            new=AsyncMock(return_value=_document(LegalSubjectScope.WORKSPACE)),
        ),
        patch.object(services, "LegalAcceptance", acceptance_cls),
        patch.object(services, "authorize_user_sign_workspace_document", authorize),
    ):
        result = await services.accept_document(
            tenant_id="tenant-1",
            user=user,
            payload=_accept_payload("ws-1"),
            ip_address="127.0.0.1",
            user_agent="pytest",
        )
    assert result.workspace_id == "ws-1"
    authorize.assert_called_once_with(
        tenant_id="tenant-1", user=user, workspace_id="ws-1"
    )
    instance.save.assert_awaited_once_with()


def test_to_document_with_acceptance_maps_present_and_absent() -> None:
    with_acceptance = _document_dict(acceptance=_acceptance_schema().model_dump())
    result = services._to_document_with_acceptance(with_acceptance)
    assert result.acceptance.uid == "accept-1"
    assert "acceptance" not in with_acceptance

    result = services._to_document_with_acceptance(_document_dict())
    assert result.acceptance is None


@pytest.mark.asyncio
async def test_get_user_legal_documents_aggregates_and_maps() -> None:
    row = _document_dict()
    user = SimpleNamespace(uid="user-1", workspace_id=None)
    with (
        patch.object(services.LegalDocument, "adjust_pagination", return_value=(3, 7)),
        patch.object(
            services,
            "_legal_documents_with_acceptance_pipeline",
            return_value=[{"$match": {}}],
        ) as pipeline,
        patch.object(
            services, "aggregate_to_list", new=AsyncMock(return_value=[row])
        ) as aggregate,
    ):
        result = await services.get_user_legal_documents(
            tenant_id="tenant-1", user=user, offset=-1, limit=100
        )
    assert result[0].title == "Terms"
    pipeline.assert_called_once()
    aggregate.assert_awaited_once_with(services.LegalDocument, [{"$match": {}}])
