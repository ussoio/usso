"""Unit tests for pure legal document helper builders."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from apps.identity.legal import services as legal_services
from apps.identity.legal.schemas import LegalDocumentType, LegalSubjectScope


def test_legal_document_match_includes_type_and_active() -> None:
    """Match stage includes document_type and is_active when provided."""
    match = legal_services._legal_document_match(
        tenant_id="t1",
        subject_scope=LegalSubjectScope.USER,
        is_active=True,
        acceptance_status=None,
        document_type=LegalDocumentType.TERMS,
    )
    assert match["tenant_id"] == "t1"
    assert match["subject_scope"] == LegalSubjectScope.USER.value
    assert match["document_type"] == LegalDocumentType.TERMS.value
    assert match["is_active"] is True


def test_legal_document_match_skips_active_for_pending() -> None:
    """Pending acceptance filter omits is_active from the first match."""
    match = legal_services._legal_document_match(
        tenant_id="t1",
        subject_scope=LegalSubjectScope.WORKSPACE,
        is_active=True,
        acceptance_status="pending",
        document_type=None,
    )
    assert "is_active" not in match
    assert match["subject_scope"] == LegalSubjectScope.WORKSPACE.value


def test_legal_acceptance_lookup_user_scope() -> None:
    """User-scoped lookup filters acceptances by user_id."""
    settings = MagicMock()
    settings.name = "legal_acceptances"
    with patch.object(
        legal_services.LegalAcceptance, "get_settings", return_value=settings
    ):
        stages = legal_services._legal_acceptance_lookup(
            subject_scope=LegalSubjectScope.USER,
            user_id="u1",
            workspace_id=None,
        )
    assert len(stages) == 2
    assert stages[0]["$lookup"]["foreignField"] == "document_id"
    cond = stages[1]["$addFields"]["acceptance_docs"]["$filter"]["cond"]
    assert {"$eq": ["$$acc.user_id", "u1"]} in cond["$and"]


def test_legal_acceptance_lookup_workspace_scope() -> None:
    """Workspace-scoped lookup filters acceptances by workspace_id."""
    settings = MagicMock()
    settings.name = "legal_acceptances"
    with patch.object(
        legal_services.LegalAcceptance, "get_settings", return_value=settings
    ):
        stages = legal_services._legal_acceptance_lookup(
            subject_scope=LegalSubjectScope.WORKSPACE,
            user_id="u1",
            workspace_id="ws-1",
        )
    cond = stages[1]["$addFields"]["acceptance_docs"]["$filter"]["cond"]
    assert {"$eq": ["$$acc.workspace_id", "ws-1"]} in cond["$and"]


def test_legal_documents_pipeline_pending_adds_size_match() -> None:
    """Pending status appends an empty-acceptance match stage."""
    user = SimpleNamespace(uid="u1", workspace_id="ws-1")
    settings = MagicMock()
    settings.name = "legal_acceptances"
    with patch.object(
        legal_services.LegalAcceptance, "get_settings", return_value=settings
    ):
        pipeline = legal_services._legal_documents_with_acceptance_pipeline(
            tenant_id="t1",
            user=user,
            offset=0,
            limit=10,
            is_active=True,
            acceptance_status="pending",
            subject_scope=LegalSubjectScope.USER,
            document_type=None,
        )
    assert {"$match": {"is_active": True, "acceptance_docs": {"$size": 0}}} in pipeline
    assert {"$skip": 0} in pipeline
    assert {"$limit": 10} in pipeline


def test_authorize_user_sign_workspace_document_allows_scope() -> None:
    """Scoped create:sso/legal-acceptance authorizes workspace signing."""
    user = SimpleNamespace(
        tenant_id="t1",
        scopes=["create:sso/legal-acceptance?workspace_id=ws-1"],
    )
    result = legal_services.authorize_user_sign_workspace_document(
        tenant_id="t1", user=user, workspace_id="ws-1"
    )
    assert result is user
