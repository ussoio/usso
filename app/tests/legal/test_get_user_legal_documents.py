"""Tests for get_user_legal_documents aggregation."""

from datetime import datetime

import pytest
import pytest_asyncio
from fastapi_mongo_base.utils import timezone
from usso import UserData

from apps.identity.legal import services
from apps.identity.legal.models import LegalAcceptance, LegalDocument
from apps.identity.legal.schemas import (
    LegalAcceptanceSource,
    LegalDocumentType,
    LegalSubjectScope,
)
from apps.tenant.models import Tenant


def _user_data(
    *,
    uid: str,
    tenant_id: str,
    workspace_id: str | None = None,
) -> UserData:
    return UserData(sub=uid, tenant_id=tenant_id, workspace_id=workspace_id)


async def _create_document(
    *,
    tenant_id: str,
    version: str,
    document_type: LegalDocumentType = LegalDocumentType.TERMS,
    subject_scope: LegalSubjectScope = LegalSubjectScope.USER,
    is_active: bool = True,
    title: str = "Test document",
) -> LegalDocument:
    return await LegalDocument(
        tenant_id=tenant_id,
        document_type=document_type,
        subject_scope=subject_scope,
        version=version,
        title=title,
        content=f"# {title}",
        is_active=is_active,
        effective_at=datetime.now(timezone.tz),
    ).save()


async def _create_acceptance(
    *,
    tenant_id: str,
    document: LegalDocument,
    user_id: str,
    workspace_id: str | None = None,
) -> LegalAcceptance:
    return await LegalAcceptance(
        tenant_id=tenant_id,
        user_id=user_id,
        subject_scope=document.subject_scope,
        workspace_id=workspace_id,
        document_id=document.uid,
        document_type=document.document_type,
        document_version=document.version,
        document_content_hash=document.content_hash,
        accepted_at=datetime.now(timezone.tz),
        ip_address="127.0.0.1",
        user_agent="pytest",
        source=LegalAcceptanceSource.LOGIN,
    ).save()


@pytest_asyncio.fixture
def legal_tenant(initial_tenant: Tenant) -> Tenant:
    """Tenant used for legal document service tests."""
    return initial_tenant


@pytest_asyncio.fixture(autouse=True)
async def cleanup_legal_data(legal_tenant: Tenant) -> None:
    """Remove legal documents and acceptances created during tests."""
    yield
    await LegalAcceptance.find({"tenant_id": legal_tenant.uid}).delete()
    await LegalDocument.find({"tenant_id": legal_tenant.uid}).delete()


@pytest.mark.asyncio
async def test_attaches_acceptance_for_current_user(
    legal_tenant: Tenant,
) -> None:
    """Accepted documents include the matching LegalAcceptance."""
    document = await _create_document(
        tenant_id=legal_tenant.uid,
        version="accepted-v1",
    )
    await _create_acceptance(
        tenant_id=legal_tenant.uid,
        document=document,
        user_id="user-a",
    )

    results = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
    )

    assert len(results) == 1
    assert results[0].uid == document.uid
    assert results[0].acceptance is not None
    assert results[0].acceptance.document_id == document.uid
    assert results[0].acceptance.user_id == "user-a"


@pytest.mark.asyncio
async def test_returns_null_acceptance_when_not_accepted(
    legal_tenant: Tenant,
) -> None:
    """Documents without acceptance are returned with acceptance=None."""
    document = await _create_document(
        tenant_id=legal_tenant.uid,
        version="open-v1",
    )

    results = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
    )

    assert len(results) == 1
    assert results[0].uid == document.uid
    assert results[0].acceptance is None


@pytest.mark.asyncio
async def test_does_not_attach_other_users_acceptance(
    legal_tenant: Tenant,
) -> None:
    """Acceptance lookup is scoped to the requesting user."""
    document = await _create_document(
        tenant_id=legal_tenant.uid,
        version="shared-v1",
    )
    await _create_acceptance(
        tenant_id=legal_tenant.uid,
        document=document,
        user_id="user-a",
    )

    results = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-b", tenant_id=legal_tenant.uid),
    )

    assert len(results) == 1
    assert results[0].acceptance is None


@pytest.mark.asyncio
async def test_pending_returns_only_active_unaccepted_documents(
    legal_tenant: Tenant,
) -> None:
    """Pending filter requires active documents with no acceptance."""
    pending_doc = await _create_document(
        tenant_id=legal_tenant.uid,
        version="pending-v1",
        is_active=True,
    )
    accepted_doc = await _create_document(
        tenant_id=legal_tenant.uid,
        version="accepted-v1",
        document_type=LegalDocumentType.PRIVACY_POLICY,
        is_active=True,
    )
    _ = await _create_document(
        tenant_id=legal_tenant.uid,
        version="inactive-v1",
        document_type=LegalDocumentType.SERVICE_CONTRACT,
        is_active=False,
    )
    await _create_acceptance(
        tenant_id=legal_tenant.uid,
        document=accepted_doc,
        user_id="user-a",
    )

    results = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
        acceptance_status="pending",
    )

    assert [item.uid for item in results] == [pending_doc.uid]
    assert all(item.is_active for item in results)
    assert all(item.acceptance is None for item in results)


@pytest.mark.asyncio
async def test_filters_by_document_type(legal_tenant: Tenant) -> None:
    """document_type query filter limits returned documents."""
    terms = await _create_document(
        tenant_id=legal_tenant.uid,
        version="terms-v1",
        document_type=LegalDocumentType.TERMS,
    )
    await _create_document(
        tenant_id=legal_tenant.uid,
        version="privacy-v1",
        document_type=LegalDocumentType.PRIVACY_POLICY,
    )

    results = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
        document_type=LegalDocumentType.TERMS,
    )

    assert len(results) == 1
    assert results[0].uid == terms.uid


@pytest.mark.asyncio
async def test_filters_by_is_active(legal_tenant: Tenant) -> None:
    """is_active filter excludes inactive documents when not pending."""
    active = await _create_document(
        tenant_id=legal_tenant.uid,
        version="active-v1",
        is_active=True,
    )
    await _create_document(
        tenant_id=legal_tenant.uid,
        version="inactive-v1",
        document_type=LegalDocumentType.PRIVACY_POLICY,
        is_active=False,
    )

    results = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
        is_active=True,
    )

    assert len(results) == 1
    assert results[0].uid == active.uid


@pytest.mark.asyncio
async def test_workspace_scope_joins_by_workspace_id(
    legal_tenant: Tenant,
) -> None:
    """Workspace-scoped acceptances match user.workspace_id."""
    document = await _create_document(
        tenant_id=legal_tenant.uid,
        version="ws-v1",
        subject_scope=LegalSubjectScope.WORKSPACE,
    )
    await _create_acceptance(
        tenant_id=legal_tenant.uid,
        document=document,
        user_id="signer",
        workspace_id="ws-1",
    )

    matched = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(
            uid="signer",
            tenant_id=legal_tenant.uid,
            workspace_id="ws-1",
        ),
        subject_scope=LegalSubjectScope.WORKSPACE,
    )
    unmatched = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(
            uid="signer",
            tenant_id=legal_tenant.uid,
            workspace_id="ws-2",
        ),
        subject_scope=LegalSubjectScope.WORKSPACE,
    )

    assert len(matched) == 1
    assert matched[0].acceptance is not None
    assert matched[0].acceptance.workspace_id == "ws-1"
    assert len(unmatched) == 1
    assert unmatched[0].acceptance is None


@pytest.mark.asyncio
async def test_pagination_offset_and_limit(legal_tenant: Tenant) -> None:
    """Results respect offset and limit."""
    await _create_document(
        tenant_id=legal_tenant.uid,
        version="page-v1",
        title="First",
    )
    await _create_document(
        tenant_id=legal_tenant.uid,
        version="page-v2",
        document_type=LegalDocumentType.PRIVACY_POLICY,
        title="Second",
    )
    await _create_document(
        tenant_id=legal_tenant.uid,
        version="page-v3",
        document_type=LegalDocumentType.SERVICE_CONTRACT,
        title="Third",
    )

    first_page = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
        offset=0,
        limit=2,
    )
    second_page = await services.get_user_legal_documents(
        tenant_id=legal_tenant.uid,
        user=_user_data(uid="user-a", tenant_id=legal_tenant.uid),
        offset=2,
        limit=2,
    )

    assert len(first_page) == 2
    assert len(second_page) == 1
    assert {item.uid for item in first_page}.isdisjoint({
        item.uid for item in second_page
    })
