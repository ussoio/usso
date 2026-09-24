"""Focused route coverage for legal documents and acceptances."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Response
from usso import USSOException

from apps.identity.legal import routes, schemas
from server.exceptions import NotFoundError


@pytest.mark.asyncio
@pytest.mark.parametrize("access_wins", [True, False])
async def test_get_user_access_or_temporary_accepts_either_token(
    access_wins: bool,
) -> None:
    router = routes.LegalDocumentRouter()
    access_user = SimpleNamespace(uid="access") if access_wins else None
    temporary_user = SimpleNamespace(uid="temporary")
    access_auth = SimpleNamespace(
        usso_access_security_async=AsyncMock(return_value=access_user)
    )
    temporary_auth = SimpleNamespace(
        usso_access_security_async=AsyncMock(return_value=temporary_user)
    )
    tenant = SimpleNamespace(
        get_auth=MagicMock(return_value=access_auth), temporary_auth=temporary_auth
    )
    with patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)):
        result = await router.get_user_access_or_temporary(MagicMock())

    assert result.uid == ("access" if access_wins else "temporary")
    access_auth.usso_access_security_async.assert_awaited_once()
    temporary_auth.usso_access_security_async.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_user_access_or_temporary_handles_unauthenticated_request() -> None:
    router = routes.LegalDocumentRouter()
    auth = SimpleNamespace(usso_access_security_async=AsyncMock(return_value=None))
    tenant = SimpleNamespace(get_auth=MagicMock(return_value=auth), temporary_auth=auth)
    with patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)):
        assert (
            await router.get_user_access_or_temporary(
                MagicMock(), raise_exception=False
            )
            is None
        )
        with pytest.raises(USSOException) as exc:
            await router.get_user_access_or_temporary(MagicMock())
    assert exc.value.error_code == "unauthorized"


@pytest.mark.asyncio
async def test_list_active_public_sets_cache_header_and_returns_page() -> None:
    router = routes.LegalDocumentRouter()
    request = MagicMock()
    response = Response()
    tenant = SimpleNamespace(uid="t1")
    documents = [object()]
    page = object()
    with (
        patch.object(routes, "get_request_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            routes.services,
            "get_public_active_documents",
            new=AsyncMock(return_value=documents),
        ) as get_documents,
        patch.object(routes, "as_page", return_value=page),
    ):
        result = await router.list_active_public(
            request,
            response,
            offset=3,
            limit=5,
            subject_scope=schemas.LegalSubjectScope.USER,
            document_type=schemas.LegalDocumentType.TERMS,
        )

    assert result is page
    assert response.headers["Cache-Control"].startswith("public, max-age=")
    get_documents.assert_awaited_once_with(
        offset=3,
        limit=5,
        tenant_id="t1",
        subject_scope=schemas.LegalSubjectScope.USER,
        document_type=schemas.LegalDocumentType.TERMS,
    )


def test_get_list_filter_queries_empty_and_broadest_paths() -> None:
    router = routes.LegalDocumentRouter()
    user = SimpleNamespace(scopes=[])
    with (
        patch.object(router, "self_access", new=False),
        patch("usso.authorization.get_scope_filters", return_value=[]),
    ):
        assert router.get_list_filter_queries(user=user) == {}

    matches = [{"document_type": "terms"}]
    with (
        patch.object(router, "self_access", new=False),
        patch("usso.authorization.get_scope_filters", return_value=matches),
        patch(
            "usso.authorization.broadest_scope_filter",
            return_value={"document_type": "terms"},
        ),
    ):
        assert router.get_list_filter_queries(user=user) == {"document_type": "terms"}


@pytest.mark.asyncio
async def test_list_items_unauthenticated_delegates_to_public_list() -> None:
    router = routes.LegalDocumentRouter()
    request = MagicMock()
    response = Response()
    list_active_public = AsyncMock(return_value="public-page")
    with (
        patch.object(
            router,
            "get_tenant",
            new=AsyncMock(return_value=SimpleNamespace(uid="t1")),
        ),
        patch.object(
            router,
            "get_user_access_or_temporary",
            new=AsyncMock(return_value=None),
        ),
        patch.object(router, "list_active_public", new=list_active_public),
    ):
        result = await router.list_items(
            request,
            response,
            offset=1,
            limit=2,
            subject_scope=schemas.LegalSubjectScope.USER,
            document_type=schemas.LegalDocumentType.PRIVACY_POLICY,
        )

    assert result == "public-page"
    list_active_public.assert_awaited_once_with(
        request=request,
        response=response,
        offset=1,
        limit=2,
        subject_scope=schemas.LegalSubjectScope.USER,
        document_type=schemas.LegalDocumentType.PRIVACY_POLICY,
    )


@pytest.mark.asyncio
async def test_list_items_authenticated_uses_user_documents() -> None:
    router = routes.LegalDocumentRouter()
    request = MagicMock()
    tenant = SimpleNamespace(uid="t1")
    user = SimpleNamespace(uid="u1")
    documents = [object()]
    with (
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(
            router,
            "get_user_access_or_temporary",
            new=AsyncMock(return_value=user),
        ),
        patch.object(
            routes.services,
            "get_user_legal_documents",
            new=AsyncMock(return_value=documents),
        ) as get_documents,
        patch.object(routes, "as_page", return_value="user-page"),
    ):
        result = await router.list_items(
            request,
            Response(),
            offset=4,
            limit=6,
            is_active=True,
            acceptance_status="pending",
            subject_scope=schemas.LegalSubjectScope.WORKSPACE,
            document_type=schemas.LegalDocumentType.TERMS,
        )
    assert result == "user-page"
    get_documents.assert_awaited_once_with(
        tenant_id="t1",
        user=user,
        offset=4,
        limit=6,
        is_active=True,
        acceptance_status="pending",
        subject_scope=schemas.LegalSubjectScope.WORKSPACE,
        document_type=schemas.LegalDocumentType.TERMS,
    )


@pytest.mark.asyncio
async def test_create_item_authorizes_and_publishes_document() -> None:
    router = routes.LegalDocumentRouter()
    user = SimpleNamespace(uid="u1")
    tenant = SimpleNamespace(uid="t1")
    payload = schemas.LegalDocumentCreateSchema(
        document_type=schemas.LegalDocumentType.TERMS,
        version="v1",
        title="Terms",
        content="Terms body",
    )
    published = object()
    validated = object()
    authorize = AsyncMock()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "authorize", new=authorize),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(routes, "require_secure_token") as require_secure,
        patch.object(
            routes.services,
            "publish_document",
            new=AsyncMock(return_value=published),
        ) as publish,
        patch.object(
            routes.schemas.LegalDocumentSchema,
            "model_validate",
            return_value=validated,
        ),
    ):
        result = await router.create_item(MagicMock(), payload)
    assert result is validated
    authorize.assert_awaited_once_with(action="create", user=user)
    require_secure.assert_called_once()
    publish.assert_awaited_once_with(tenant_id="t1", payload=payload)


@pytest.mark.asyncio
async def test_accept_item_passes_request_metadata() -> None:
    router = routes.LegalDocumentRouter()
    request = MagicMock()
    user = SimpleNamespace(uid="u1")
    tenant = SimpleNamespace(uid="t1")
    data = schemas.LegalAcceptanceCreateSchema(document_id="doc-1")
    accepted = object()
    with (
        patch.object(
            router,
            "get_user_access_or_temporary",
            new=AsyncMock(return_value=user),
        ),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch("utils.net.get_client_ip", return_value="127.0.0.1"),
        patch("utils.net.get_client_user_agent", return_value="pytest"),
        patch.object(
            routes.services,
            "accept_document",
            new=AsyncMock(return_value=accepted),
        ) as accept,
    ):
        result = await router.accept_item(request, data)
    assert result is accepted
    accept.assert_awaited_once_with(
        tenant_id="t1",
        user=user,
        payload=data,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )


@pytest.mark.asyncio
async def test_last_public_raises_when_empty_and_validates_first_item() -> None:
    router = routes.LegalDocumentRouter()
    with (
        patch.object(
            router,
            "list_active_public",
            new=AsyncMock(return_value=SimpleNamespace(items=[])),
        ),
        pytest.raises(NotFoundError) as exc,
    ):
        await router.last_public(
            MagicMock(),
            Response(),
            schemas.LegalDocumentType.TERMS,
            schemas.LegalSubjectScope.USER,
        )
    assert exc.value.error_code == "legal_document_not_found"

    first = object()
    validated = object()
    with (
        patch.object(
            router,
            "list_active_public",
            new=AsyncMock(return_value=SimpleNamespace(items=[first, object()])),
        ),
        patch.object(
            routes.schemas.LegalDocumentWithAcceptanceResponseSchema,
            "model_validate",
            return_value=validated,
        ) as model_validate,
    ):
        result = await router.last_public(
            MagicMock(),
            Response(),
            schemas.LegalDocumentType.TERMS,
            schemas.LegalSubjectScope.USER,
        )
    assert result is validated
    model_validate.assert_called_once_with(first)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("subject_scope", "subject_filter"),
    [
        (schemas.LegalSubjectScope.USER, {"user_id": "u1"}),
        (schemas.LegalSubjectScope.WORKSPACE, {"workspace_id": "ws-1"}),
    ],
)
async def test_acceptance_list_items_applies_subject_authorization(
    subject_scope: schemas.LegalSubjectScope, subject_filter: dict
) -> None:
    router = routes.LegalAcceptanceRouter()
    request = MagicMock()
    user = SimpleNamespace(uid="u1")
    tenant = SimpleNamespace(uid="t1")
    list_items = AsyncMock(return_value="page")
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(router, "_list_items", new=list_items),
        patch.object(
            routes.services,
            "authorize_workspace_document_signing",
            new=AsyncMock(),
        ) as authorize_workspace,
    ):
        result = await router.list_items(
            request,
            offset=1,
            limit=3,
            subject_scope=subject_scope,
            workspace_id="ws-1",
            document_type=schemas.LegalDocumentType.TERMS,
        )
    assert result == "page"
    if subject_scope == schemas.LegalSubjectScope.WORKSPACE:
        authorize_workspace.assert_awaited_once_with(
            tenant_id="t1", user_id="u1", workspace_id="ws-1"
        )
    else:
        authorize_workspace.assert_not_awaited()
    list_items.assert_awaited_once_with(
        request=request,
        offset=1,
        limit=3,
        subject_scope=subject_scope,
        document_type=schemas.LegalDocumentType.TERMS,
        **subject_filter,
    )


@pytest.mark.asyncio
async def test_acceptance_create_and_retrieve_delegate_services_and_authorize() -> None:
    router = routes.LegalAcceptanceRouter()
    request = MagicMock()
    user = SimpleNamespace(uid="u1", tenant_id="t1")
    tenant = SimpleNamespace(uid="t1")
    data = schemas.LegalAcceptanceCreateSchema(document_id="doc-1")
    accepted = object()
    item = SimpleNamespace(model_dump=MagicMock(return_value={"uid": "acc-1"}))
    get_item = AsyncMock(return_value=item)
    authorize = AsyncMock()
    with (
        patch.object(router, "get_user", new=AsyncMock(return_value=user)),
        patch.object(router, "get_tenant", new=AsyncMock(return_value=tenant)),
        patch.object(router, "get_item", new=get_item),
        patch.object(router, "authorize", new=authorize),
        patch.object(
            routes.services,
            "accept_document",
            new=AsyncMock(return_value=accepted),
        ) as accept,
    ):
        assert await router.create_item(request, data) is accepted
        assert await router.retrieve_item(request, "acc-1") is item
    accept.assert_awaited_once_with(
        tenant_id="t1", signatory_user_id="u1", payload=data, request=request
    )
    get_item.assert_awaited_once_with(
        uid="acc-1", tenant_id="t1", **{router.owner_attr: None}
    )
    authorize.assert_awaited_once_with(
        action="read", user=user, filter_data={"uid": "acc-1"}
    )
