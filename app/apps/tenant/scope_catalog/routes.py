"""HTTP routes for the per-tenant scope catalog."""

from fastapi import Query, Request
from fastapi_mongo_base.schemas import PaginatedResponse
from usso import UserData

from server.config import Settings
from utils.usso_routes import AbstractTenantUSSORouter

from . import models, schemas, services


class ScopeCatalogRouter(AbstractTenantUSSORouter):
    """
    Catalog of scopes declared by microservices (selection UX only).

    Authorization still uses JWT scopes; this API is not an authz source of truth.
    """

    model = models.ScopeCatalog
    schema = schemas.ScopeCatalogSchema
    resource = "scope_catalog"
    self_access = False

    def __init__(self) -> None:
        """Initialize scope catalog router."""
        super().__init__(prefix="/scope-catalog", tags=["Scope Catalog"])

    def config_routes(self, **kwargs: object) -> None:
        """Register sync + standard CRUD (manual create/update/delete)."""
        self.router.add_api_route(
            "/{service}",
            self.sync_service_scopes,
            methods=["PUT"],
            status_code=200,
            response_model=list[schemas.ScopeCatalogSchema],
        )
        super().config_routes(**kwargs)

    async def list_items(
        self,
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=Settings.page_max_limit),
        service: str | None = Query(
            None,
            description="Filter by registering service name (e.g. media).",
        ),
        source: schemas.ScopeCatalogSource | None = Query(
            None,
            description="Filter by catalog source.",
        ),
        scope: str | None = Query(
            None,
            description="Exact scope string filter.",
        ),
    ) -> PaginatedResponse[schemas.ScopeCatalogSchema]:
        """List catalog entries for the current tenant."""
        filters: dict = {}
        if service is not None:
            filters["service"] = services.normalize_service_name(service)
        if source is not None:
            filters["source"] = source
        if scope is not None:
            filters["scope"] = scope.strip()
        return await self._list_items(
            request=request,
            offset=offset,
            limit=limit,
            **filters,
        )

    async def sync_service_scopes(
        self,
        request: Request,
        service: str,
        data: schemas.ScopeCatalogSyncSchema,
    ) -> list[models.ScopeCatalog]:
        """Replace service-sourced scopes for ``service`` (startup push)."""
        user = await self.get_user(request)
        await self.authorize(
            action="manage",
            user=user,
            filter_data={"service": services.normalize_service_name(service)},
        )
        tenant = await self.get_tenant(request)
        return await services.sync_service_scopes(
            tenant_id=tenant.uid,
            service=service,
            items=data.scopes,
        )

    async def create_item(
        self,
        request: Request,
        data: schemas.ScopeCatalogCreateSchema,
    ) -> models.ScopeCatalog:
        """Create a manually curated catalog entry."""
        user = await self.get_user(request)
        await self.authorize(
            action="create",
            user=user,
            filter_data=data.model_dump(),
        )
        tenant = await self.get_tenant(request)
        return await services.create_manual_entry(
            tenant_id=tenant.uid,
            data=data,
        )

    async def update_item(
        self,
        request: Request,
        uid: str,
        data: schemas.ScopeCatalogUpdateSchema,
    ) -> models.ScopeCatalog:
        """Update display metadata without exposing persisted ownership fields."""
        return await super().update_item(
            request,
            uid,
            data.model_dump(exclude_unset=True),
        )

    def get_list_filter_queries(self, *, user: UserData) -> dict:
        """Tenant-scoped list; require read scope (no self-access ownership)."""
        from usso import authorization

        matched_scopes: list[dict] = authorization.get_scope_filters(
            action="read",
            resource=self.resource_path,
            user_scopes=user.scopes if user else [],
        )
        if not matched_scopes:
            return {"__deny__": True}
        return authorization.broadest_scope_filter(matched_scopes)


router = ScopeCatalogRouter().router
