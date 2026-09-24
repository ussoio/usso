"""Legal document and acceptance services."""

from datetime import datetime
from typing import Literal

from aiocache import cached
from fastapi_mongo_base.utils import timezone
from fastapi_mongo_base.utils.mongo_aggregate import aggregate_to_list
from usso import UserData, authorization

from apps.identity.user.models import User
from server.exceptions import (
    BadRequestError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
)

from .models import LegalAcceptance, LegalDocument
from .schemas import (
    LegalAcceptanceCreateSchema,
    LegalAcceptanceSchema,
    LegalDocumentCreateSchema,
    LegalDocumentType,
    LegalDocumentWithAcceptanceResponseSchema,
    LegalSubjectScope,
)

_SIGN_SCOPE = "create:sso/legal-acceptance"
PUBLIC_ACTIVE_DOCUMENTS_CACHE_TTL = 300


async def authorize_workspace_document_signing(
    *,
    tenant_id: str,
    user_id: str,
    workspace_id: str | None,
) -> User:
    """Load a user and verify they may sign legal documents for a workspace."""
    if not workspace_id:
        raise BadRequestError(
            error_code="workspace_required",
            detail="workspace_id is required",
            message={
                "en": "workspace_id is required",
                "fa": "انتخاب فضای کاری الزامی است.",
            },
        )

    user = await User.get_item(uid=user_id, tenant_id=tenant_id)
    if user is None:
        raise NotFoundError(
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )
    if workspace_id not in (user.workspace_ids or []):
        raise ForbiddenError(
            detail="You are not a member of this workspace",
            message={
                "en": "You are not a member of this workspace",
                "fa": "عضو این فضای کاری نیستید.",
            },
        )

    if "admin" in (user.roles or []):
        return user

    # workspace_roles = (user.workspace_roles or {}).get(workspace_id) or []  # ruff:ignore[commented-out-code]
    # if "CEO" in workspace_roles:
    #     return user  # ruff:ignore[commented-out-code]

    scopes = await user.get_scopes(workspace_id) or []
    required_scope = f"{_SIGN_SCOPE}?workspace_id={workspace_id}"
    if authorization.has_subset_scope(user_scopes=scopes, subset_scope=required_scope):
        return user

    raise ForbiddenError(
        detail="You are not allowed to accept legal documents for this workspace",
        message={
            "en": "You are not allowed to accept legal documents for this workspace",
            "fa": "به پذیرش قوانین این فضای کاری دسترسی ندارید.",
        },
    )


def authorize_user_sign_workspace_document(
    *, tenant_id: str, user: UserData, workspace_id: str
) -> User:
    """Load a user and verify they may sign legal documents for a workspace."""
    if user.tenant_id != tenant_id:
        raise UnauthorizedError(
            error_code="unauthorized",
            detail="Unauthorized",
            message={"en": "Unauthorized", "fa": "لطفاً دوباره وارد شوید."},
        )

    required_scope = f"{_SIGN_SCOPE}?workspace_id={workspace_id}"
    if authorization.has_subset_scope(
        user_scopes=user.scopes, subset_scope=required_scope
    ):
        return user

    raise ForbiddenError(
        detail="You are not allowed to accept legal documents for this workspace",
        message={
            "en": "You are not allowed to accept legal documents for this workspace",
            "fa": "به پذیرش قوانین این فضای کاری دسترسی ندارید.",
        },
    )


async def publish_document(
    *, tenant_id: str, payload: LegalDocumentCreateSchema
) -> LegalDocument:
    """Publish a new legal document version for a tenant."""
    if payload.is_active:
        await LegalDocument.find({
            "tenant_id": tenant_id,
            "type": payload.document_type,
            "subject_scope": payload.subject_scope,
            "is_active": True,
            "is_deleted": False,
        }).update_many({"$set": {"is_active": False}})

    document = await LegalDocument(
        tenant_id=tenant_id,
        effective_at=payload.effective_at or datetime.now(timezone.tz),
        **payload.model_dump(exclude={"effective_at"}),
    ).save()
    return document


@cached(ttl=PUBLIC_ACTIVE_DOCUMENTS_CACHE_TTL)
async def get_public_active_documents(
    *,
    tenant_id: str,
    offset: int = 0,
    limit: int | None = None,
    subject_scope: LegalSubjectScope,
    document_type: LegalDocumentType | None = None,
) -> list[LegalDocumentWithAcceptanceResponseSchema]:
    """Return active documents for unauthenticated clients."""
    documents = await LegalDocument.get_active_documents(
        tenant_id=tenant_id,
        offset=offset,
        limit=limit,
        subject_scope=subject_scope,
        document_type=document_type,
    )
    return [
        LegalDocumentWithAcceptanceResponseSchema.model_validate(document)
        for document in documents
    ]


async def accept_document(
    *,
    tenant_id: str,
    user: UserData,
    payload: LegalAcceptanceCreateSchema,
    ip_address: str,
    user_agent: str,
) -> LegalAcceptanceSchema:
    """Record acceptance of a legal document by a user or workspace."""
    document = await LegalDocument.get_item(
        uid=payload.document_id, tenant_id=tenant_id
    )
    if not document or not document.is_active:
        raise NotFoundError(
            detail="Active legal document not found",
            message={
                "en": "Active legal document not found",
                "fa": "متن قوانین فعال پیدا نشد.",
            },
        )

    if document.subject_scope == LegalSubjectScope.USER:
        workspace_id = None
        existing = await LegalAcceptance.find_for_document(
            tenant_id=tenant_id,
            document=document,
            user_id=user.uid,
        )
    else:
        workspace_id = payload.workspace_id or user.workspace_id
        authorize_user_sign_workspace_document(
            tenant_id=tenant_id,
            user=user,
            workspace_id=workspace_id,
        )
        existing = await LegalAcceptance.find_for_document(
            tenant_id=tenant_id,
            document=document,
            workspace_id=workspace_id,
        )

    if existing:
        return LegalAcceptanceSchema.model_validate(existing)

    acceptance = await LegalAcceptance(
        tenant_id=tenant_id,
        user_id=user.uid,
        subject_scope=document.subject_scope,
        workspace_id=workspace_id,
        document_id=document.uid,
        document_type=document.document_type,
        document_version=document.version,
        document_content_hash=document.content_hash,
        accepted_at=datetime.now(timezone.tz),
        ip_address=ip_address,
        user_agent=user_agent,
        source=payload.source,
    ).save()
    return LegalAcceptanceSchema.model_validate(acceptance)


def _legal_document_match(
    *,
    tenant_id: str,
    subject_scope: LegalSubjectScope,
    is_active: bool | None,
    acceptance_status: Literal["pending"] | None,
    document_type: LegalDocumentType | None,
) -> dict:
    """Build the initial $match stage for legal document queries."""
    match: dict = {
        "tenant_id": tenant_id,
        "is_deleted": False,
        "subject_scope": subject_scope.value,
    }
    if document_type is not None:
        match["document_type"] = document_type.value
    if is_active is not None and acceptance_status != "pending":
        match["is_active"] = is_active
    return match


def _legal_acceptance_lookup(
    *,
    subject_scope: LegalSubjectScope,
    user_id: str,
    workspace_id: str | None,
) -> list[dict]:
    """Build lookup and subject-filter stages for acceptances."""
    subject_field = (
        "user_id" if subject_scope == LegalSubjectScope.USER else "workspace_id"
    )
    subject_value = user_id if subject_scope == LegalSubjectScope.USER else workspace_id

    return [
        {
            "$lookup": {
                "from": LegalAcceptance.get_settings().name,
                "localField": "uid",
                "foreignField": "document_id",
                "as": "acceptance_docs",
            }
        },
        {
            "$addFields": {
                "acceptance_docs": {
                    "$filter": {
                        "input": "$acceptance_docs",
                        "as": "acc",
                        "cond": {
                            "$and": [
                                {"$eq": ["$$acc.tenant_id", "$tenant_id"]},
                                {"$eq": ["$$acc.is_deleted", False]},
                                {
                                    "$eq": [
                                        "$$acc.subject_scope",
                                        subject_scope.value,
                                    ]
                                },
                                {"$eq": [f"$$acc.{subject_field}", subject_value]},
                            ]
                        },
                    }
                }
            }
        },
    ]


def _legal_documents_with_acceptance_pipeline(
    *,
    tenant_id: str,
    user: UserData,
    offset: int,
    limit: int,
    is_active: bool | None,
    acceptance_status: Literal["pending"] | None,
    subject_scope: LegalSubjectScope,
    document_type: LegalDocumentType | None,
) -> list[dict]:
    """Build an aggregation pipeline for documents with optional acceptance."""
    pipeline: list[dict] = [
        {
            "$match": _legal_document_match(
                tenant_id=tenant_id,
                subject_scope=subject_scope,
                is_active=is_active,
                acceptance_status=acceptance_status,
                document_type=document_type,
            )
        },
        *_legal_acceptance_lookup(
            subject_scope=subject_scope,
            user_id=user.uid,
            workspace_id=user.workspace_id,
        ),
    ]
    if acceptance_status == "pending":
        pipeline.append({
            "$match": {
                "is_active": True,
                "acceptance_docs": {"$size": 0},
            }
        })
    pipeline.extend([
        {
            "$addFields": {
                "acceptance": {"$arrayElemAt": ["$acceptance_docs", 0]},
            }
        },
        {"$sort": {"created_at": -1}},
        {"$skip": offset},
        {"$limit": limit},
        {"$project": {"acceptance_docs": 0, "_id": 0}},
    ])
    return pipeline


def _to_document_with_acceptance(
    item: dict,
) -> LegalDocumentWithAcceptanceResponseSchema:
    """Map an aggregation result row to the response schema."""
    acceptance_data = item.pop("acceptance", None)
    acceptance = (
        LegalAcceptanceSchema.model_validate(acceptance_data)
        if acceptance_data
        else None
    )
    return LegalDocumentWithAcceptanceResponseSchema.model_validate({
        **item,
        "acceptance": acceptance,
    })


async def get_user_legal_documents(
    *,
    tenant_id: str,
    user: UserData,
    offset: int = 0,
    limit: int = 10,
    is_active: bool | None = None,
    acceptance_status: Literal["pending"] | None = None,
    subject_scope: LegalSubjectScope = LegalSubjectScope.USER,
    document_type: LegalDocumentType | None = None,
) -> list[LegalDocumentWithAcceptanceResponseSchema]:
    """Get the legal documents for a user."""
    offset, limit = LegalDocument.adjust_pagination(offset, limit)
    pipeline = _legal_documents_with_acceptance_pipeline(
        tenant_id=tenant_id,
        user=user,
        offset=offset,
        limit=limit,
        is_active=is_active,
        acceptance_status=acceptance_status,
        subject_scope=subject_scope,
        document_type=document_type,
    )
    rows = await aggregate_to_list(LegalDocument, pipeline)
    result = [_to_document_with_acceptance(row) for row in rows]
    return result
