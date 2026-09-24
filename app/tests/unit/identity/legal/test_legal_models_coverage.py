"""Unit coverage for legal document and acceptance model helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.identity.legal.models import LegalAcceptance, LegalDocument
from apps.identity.legal.schemas import LegalDocumentType, LegalSubjectScope


@pytest.mark.asyncio
async def test_get_active_documents_forwards_all_filters() -> None:
    documents = [SimpleNamespace(uid="doc-1")]
    with patch.object(
        LegalDocument, "list_items", new=AsyncMock(return_value=documents)
    ) as list_items:
        result = await LegalDocument.get_active_documents(
            tenant_id="tenant-1",
            offset=2,
            limit=5,
            subject_scope=LegalSubjectScope.WORKSPACE,
            document_type=LegalDocumentType.TERMS,
        )
    assert result is documents
    list_items.assert_awaited_once_with(
        tenant_id="tenant-1",
        offset=2,
        limit=5,
        is_active=True,
        is_deleted=False,
        subject_scope=LegalSubjectScope.WORKSPACE,
        type=LegalDocumentType.TERMS,
    )


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (
            LegalSubjectScope.USER,
            {
                "tenant_id": "tenant-1",
                "subject_scope": LegalSubjectScope.USER,
                "user_id": "user-1",
            },
        ),
        (
            LegalSubjectScope.WORKSPACE,
            {
                "tenant_id": "tenant-1",
                "subject_scope": LegalSubjectScope.WORKSPACE,
                "workspace_id": "ws-1",
            },
        ),
    ],
)
def test_subject_query_selects_scope_owner(
    scope: LegalSubjectScope, expected: dict
) -> None:
    assert (
        LegalAcceptance._subject_query(
            tenant_id="tenant-1",
            subject_scope=scope,
            user_id="user-1",
            workspace_id="ws-1",
        )
        == expected
    )


@pytest.mark.asyncio
async def test_find_for_document_builds_acceptance_query() -> None:
    document = SimpleNamespace(uid="doc-1", subject_scope=LegalSubjectScope.WORKSPACE)
    acceptance = SimpleNamespace(uid="acceptance-1")
    with patch.object(
        LegalAcceptance, "find_one", new=AsyncMock(return_value=acceptance)
    ) as find:
        result = await LegalAcceptance.find_for_document(
            tenant_id="tenant-1",
            document=document,
            user_id="user-1",
            workspace_id="ws-1",
        )
    assert result is acceptance
    find.assert_awaited_once_with({
        "tenant_id": "tenant-1",
        "subject_scope": LegalSubjectScope.WORKSPACE,
        "workspace_id": "ws-1",
        "document_id": "doc-1",
        "is_deleted": False,
    })


@pytest.mark.asyncio
@pytest.mark.parametrize("acceptances", [[SimpleNamespace(uid="a-1")], []])
async def test_get_latest_for_subject_sorts_limits_and_handles_empty(
    acceptances: list,
) -> None:
    query = MagicMock()
    query.sort.return_value = query
    query.limit.return_value = query
    query.to_list = AsyncMock(return_value=acceptances)
    with patch.object(LegalAcceptance, "get_query", return_value=query) as get_query:
        result = await LegalAcceptance.get_latest_for_subject(
            tenant_id="tenant-1",
            document_type=LegalDocumentType.PRIVACY_POLICY,
            subject_scope=LegalSubjectScope.USER,
            user_id="user-1",
        )
    assert result is (acceptances[0] if acceptances else None)
    get_query.assert_called_once_with(
        tenant_id="tenant-1",
        subject_scope=LegalSubjectScope.USER,
        user_id="user-1",
        document_type=LegalDocumentType.PRIVACY_POLICY,
    )
    query.sort.assert_called_once_with("accepted_at", -1)
    query.limit.assert_called_once_with(1)
    query.to_list.assert_awaited_once_with()
