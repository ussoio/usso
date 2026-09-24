"""Legal document and acceptance models."""

from typing import ClassVar, Self

from fastapi_mongo_base.models import (
    ASCENDING,
    IndexModel,
    TenantScopedEntity,
    TenantUserEntity,
)

from .schemas import (
    LegalAcceptanceSchema,
    LegalDocumentSchema,
    LegalDocumentType,
    LegalSubjectScope,
)


class LegalDocument(LegalDocumentSchema, TenantScopedEntity):
    """Tenant-scoped legal document version."""

    class Settings:
        """Legal document settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantScopedEntity.Settings.indexes,
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("document_type", ASCENDING),
                    ("subject_scope", ASCENDING),
                    ("version", ASCENDING),
                ],
                unique=True,
            ),
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("document_type", ASCENDING),
                    ("subject_scope", ASCENDING),
                    ("is_active", ASCENDING),
                ],
            ),
        ]

    @classmethod
    async def get_active_documents(
        cls,
        *,
        tenant_id: str,
        offset: int = 0,
        limit: int | None = None,
        subject_scope: LegalSubjectScope | None = None,
        document_type: LegalDocumentType | None = None,
    ) -> list[Self]:
        """Return the latest active document per type and subject scope."""
        return await cls.list_items(
            tenant_id=tenant_id,
            offset=offset,
            limit=limit,
            is_active=True,
            is_deleted=False,
            subject_scope=subject_scope,
            type=document_type,
        )


class LegalAcceptance(LegalAcceptanceSchema, TenantUserEntity):
    """Immutable record of a legal document acceptance."""

    class Settings:
        """Legal acceptance settings."""

        keep_nulls = False
        validate_on_save = True

        indexes: ClassVar[list[IndexModel]] = [
            *TenantUserEntity.Settings.indexes,
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("user_id", ASCENDING),
                    ("document_id", ASCENDING),
                ],
                unique=True,
                partialFilterExpression={
                    "subject_scope": LegalSubjectScope.USER,
                    "is_deleted": False,
                },
            ),
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("workspace_id", ASCENDING),
                    ("document_id", ASCENDING),
                ],
                unique=True,
                partialFilterExpression={
                    "subject_scope": LegalSubjectScope.WORKSPACE,
                    "is_deleted": False,
                },
            ),
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("workspace_id", ASCENDING),
                    ("document_type", ASCENDING),
                    ("accepted_at", ASCENDING),
                ],
            ),
            IndexModel(
                [
                    ("tenant_id", ASCENDING),
                    ("user_id", ASCENDING),
                    ("document_type", ASCENDING),
                    ("accepted_at", ASCENDING),
                ],
            ),
        ]

    @classmethod
    def _subject_query(
        cls,
        *,
        tenant_id: str,
        subject_scope: LegalSubjectScope,
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> dict:
        query = {"tenant_id": tenant_id, "subject_scope": subject_scope}
        if subject_scope == LegalSubjectScope.USER:
            query["user_id"] = user_id
        else:
            query["workspace_id"] = workspace_id
        return query

    @classmethod
    async def find_for_document(
        cls,
        *,
        tenant_id: str,
        document: LegalDocument,
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> Self | None:
        """Return an existing acceptance for this document version, if any."""
        query = {
            **cls._subject_query(
                tenant_id=tenant_id,
                subject_scope=document.subject_scope,
                user_id=user_id,
                workspace_id=workspace_id,
            ),
            "document_id": document.uid,
            "is_deleted": False,
        }
        return await cls.find_one(query)

    @classmethod
    async def get_latest_for_subject(
        cls,
        *,
        tenant_id: str,
        document_type: LegalDocumentType,
        subject_scope: LegalSubjectScope,
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> Self | None:
        """Return the latest acceptance for a subject and document type."""
        acceptances = (
            await cls
            .get_query(
                **cls._subject_query(
                    tenant_id=tenant_id,
                    subject_scope=subject_scope,
                    user_id=user_id,
                    workspace_id=workspace_id,
                ),
                document_type=document_type,
            )
            .sort("accepted_at", -1)
            .limit(1)
            .to_list()
        )
        return acceptances[0] if acceptances else None
