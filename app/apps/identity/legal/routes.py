"""Legal document and acceptance routes."""

from typing import Literal

from fastapi import Query, Request, Response
from fastapi_mongo_base.routes import as_page
from fastapi_mongo_base.schemas import PaginatedResponse
from usso import UserData

from apps.identity.auth.services import require_secure_token
from apps.tenant.services import get_request_tenant
from server.config import Settings
from server.exceptions import NotFoundError
from utils.usso_routes import AbstractTenantUSSORouter

from . import models, schemas, services


class LegalDocumentRouter(AbstractTenantUSSORouter):
    """CRUD router for tenant legal document versions."""

    model = models.LegalDocument
    schema = schemas.LegalDocumentWithAcceptanceResponseSchema
    resource = "legal_document"

    def __init__(self) -> None:
        """Initialize legal document router."""
        super().__init__(prefix="/legal/documents", tags=["Legal"])

    def config_routes(self, **kwargs: object) -> None:
        """Configure legal document collection routes."""
        self.router.add_api_route(
            "/last",
            self.last_public,
            methods=["GET"],
            status_code=200,
            response_model=schemas.LegalDocumentWithAcceptanceResponseSchema,
        )
        super().config_routes(
            mine_route=True,
            update_route=False,
            delete_route=False,
            **kwargs,
        )
        self.router.add_api_route(
            "/{uid}/acceptances",
            self.accept_item,
            methods=["POST"],
            status_code=200,
            response_model=schemas.LegalAcceptanceSchema,
        )

    async def get_user_access_or_temporary(
        self,
        request: Request,
        *,
        raise_exception: bool = True,
        **kwargs: object,
    ) -> UserData | None:
        """
        Get the authenticated user data from USSO.

        Resolves the tenant first, then uses the tenant's USSO authentication
        to get the current user.

        Args:
            request: The FastAPI request object.
            raise_exception: Whether raise exception or return None as user
            **kwargs: Additional keyword arguments.

        Returns:
            UserData instance if authenticated, None otherwise.

        """
        import asyncio

        from usso import USSOException

        tenant = await self.get_tenant(request=request, **kwargs)
        access_user, temporary_user = await asyncio.gather(
            tenant.optional_user_async(request, "access"),
            tenant.optional_user_async(request, "temporary"),
        )
        user = access_user or temporary_user
        if not user:
            if raise_exception:
                raise USSOException(
                    status_code=401,
                    error_code="unauthorized",
                    message={
                        "en": "No access or temporary token provided",
                        "fa": "لطفاً دوباره وارد شوید.",
                    },
                )
            return None
        return user

    async def list_active_public(
        self,
        request: Request,
        response: Response,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        subject_scope: schemas.LegalSubjectScope = Query(
            schemas.LegalSubjectScope.USER,
            description="Whether active documents apply to users or workspaces.",
        ),
        document_type: schemas.LegalDocumentType | None = Query(
            None,
            description="Filter by document type.",
        ),
    ) -> PaginatedResponse[schemas.LegalDocumentWithAcceptanceResponseSchema]:
        """List active legal documents without authentication."""
        response.headers["Cache-Control"] = (
            f"public, max-age={services.PUBLIC_ACTIVE_DOCUMENTS_CACHE_TTL}"
        )
        tenant = await get_request_tenant(request)
        return as_page(
            await services.get_public_active_documents(
                offset=offset,
                limit=limit,
                tenant_id=tenant.uid,
                subject_scope=subject_scope,
                document_type=document_type,
            ),
        )

    def get_list_filter_queries(self, *, user: UserData) -> dict:
        """Build list query filters from user and scopes."""
        from usso import authorization

        matched_scopes: list[dict] = authorization.get_scope_filters(
            action="read",
            resource=self.resource_path,
            user_scopes=user.scopes if user else [],
        )
        if self.self_access and hasattr(self.model, self.owner_attr):
            matched_scopes.append({self.owner_attr: self._resolve_owner_id(user)})
        elif not matched_scopes:
            return {}
        return authorization.broadest_scope_filter(matched_scopes)

    async def list_items(
        self,
        request: Request,
        response: Response,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        is_active: bool | None = Query(
            None,
            description=(
                "Filter by active status. When true, returns the latest "
                "document per type."
            ),
        ),
        acceptance_status: Literal["pending"] | None = Query(
            None,
            description=(
                'When "pending", returns active documents the subject has not accepted.'
            ),
        ),
        subject_scope: schemas.LegalSubjectScope = Query(
            schemas.LegalSubjectScope.USER,
            description=(
                "Whether pending/active documents apply to users or workspaces."
            ),
        ),
        document_type: schemas.LegalDocumentType | None = Query(
            None,
            description="Filter by document type.",
        ),
    ) -> PaginatedResponse[schemas.LegalDocumentWithAcceptanceResponseSchema]:
        """List legal documents with optional filters."""
        tenant = await self.get_tenant(request)
        user = await self.get_user_access_or_temporary(request, raise_exception=False)
        if not user:
            return await self.list_active_public(
                request=request,
                response=response,
                offset=offset,
                limit=limit,
                subject_scope=subject_scope,
                document_type=document_type,
            )

        return as_page(
            await services.get_user_legal_documents(
                tenant_id=tenant.uid,
                user=user,
                offset=offset,
                limit=limit,
                is_active=is_active,
                acceptance_status=acceptance_status,
                subject_scope=subject_scope,
                document_type=document_type,
            )
        )

    async def create_item(
        self,
        request: Request,
        item: schemas.LegalDocumentCreateSchema,
    ) -> schemas.LegalDocumentSchema:
        """Publish a new legal document version."""
        user = await self.get_user(request)
        await self.authorize(action="create", user=user)
        tenant = await self.get_tenant(request)
        require_secure_token(request=request, tenant=tenant, user_id=user.uid)
        document = await services.publish_document(tenant_id=tenant.uid, payload=item)
        return schemas.LegalDocumentSchema.model_validate(document)

    async def accept_item(
        self,
        request: Request,
        data: schemas.LegalAcceptanceCreateSchema,
    ) -> schemas.LegalAcceptanceSchema:
        """Record acceptance of a legal document version."""
        from utils import net

        user: UserData = await self.get_user_access_or_temporary(request)
        tenant = await self.get_tenant(request)
        return await services.accept_document(
            tenant_id=tenant.uid,
            user=user,
            payload=data,
            ip_address=net.get_client_ip(request),
            user_agent=net.get_client_user_agent(request),
        )

    async def last_public(
        self,
        request: Request,
        response: Response,
        document_type: schemas.LegalDocumentType,
        subject_scope: schemas.LegalSubjectScope,
    ) -> schemas.LegalDocumentWithAcceptanceResponseSchema:
        """Get the last public legal document."""
        result: PaginatedResponse[
            schemas.LegalDocumentWithAcceptanceResponseSchema
        ] = await self.list_active_public(
            request=request,
            response=response,
            offset=0,
            limit=1,
            subject_scope=subject_scope,
            document_type=document_type,
        )
        if not result.items:
            raise NotFoundError(
                error_code="legal_document_not_found",
                detail="No active legal document found",
                message={
                    "en": "No active legal document found",
                    "fa": "سند حقوقی فعالی پیدا نشد.",
                },
            )
        return schemas.LegalDocumentWithAcceptanceResponseSchema.model_validate(
            result.items[0]
        )


class LegalAcceptanceRouter(AbstractTenantUSSORouter):
    """Collection routes for legal document acceptances."""

    model = models.LegalAcceptance
    schema = schemas.LegalAcceptanceSchema
    resource = "legal_acceptance"

    def __init__(self) -> None:
        """Initialize legal acceptance router."""
        super().__init__(prefix="/acceptances", tags=["Legal"])

    def config_routes(self, **kwargs: object) -> None:
        """Configure immutable acceptance collection routes."""
        super().config_routes(update_route=False, delete_route=False, **kwargs)

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(10, ge=1, le=Settings.page_max_limit),
        subject_scope: schemas.LegalSubjectScope = Query(
            schemas.LegalSubjectScope.USER,
            description="List acceptances for a user or a workspace.",
        ),
        workspace_id: str | None = Query(
            None,
            description="Workspace subject when subject_scope is workspace.",
        ),
        document_type: schemas.LegalDocumentType | None = Query(
            None,
            description="Filter by document type.",
        ),
    ) -> PaginatedResponse[schemas.LegalAcceptanceSchema]:
        """List legal acceptances for the current user or a workspace."""
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)

        if subject_scope == schemas.LegalSubjectScope.WORKSPACE:
            await services.authorize_workspace_document_signing(
                tenant_id=tenant.uid,
                user_id=user.uid,
                workspace_id=workspace_id,
            )
            return await self._list_items(
                request=request,
                offset=offset,
                limit=limit,
                subject_scope=subject_scope,
                workspace_id=workspace_id,
                document_type=document_type,
            )

        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            subject_scope=subject_scope,
            user_id=user.uid,
            document_type=document_type,
        )

    async def create_item(
        self,
        request: Request,
        data: schemas.LegalAcceptanceCreateSchema,
    ) -> schemas.LegalAcceptanceSchema:
        """Record acceptance of a legal document version."""
        user = await self.get_user(request)
        tenant = await self.get_tenant(request)
        return await services.accept_document(
            tenant_id=tenant.uid,
            signatory_user_id=user.uid,
            payload=data,
            request=request,
        )

    async def retrieve_item(
        self,
        request: Request,
        uid: str,
    ) -> schemas.LegalDocumentWithAcceptanceResponseSchema:
        """Get a legal document by ID."""
        user = await self.get_user(request)
        item = await self.get_item(
            uid=uid, tenant_id=user.tenant_id, **{self.owner_attr: None}
        )
        await self.authorize(
            action="read",
            user=user,
            filter_data=item.model_dump(),
        )
        return item


router = LegalDocumentRouter().router
