"""Regression tests for provider-neutral workspace creation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from apps.access_control.workspace import services
from apps.access_control.workspace.schemas import WorkspaceSchema
from server.exceptions import AlreadyExistsError


@pytest.mark.asyncio
async def test_existing_slug_cannot_be_used_to_join_workspace() -> None:
    existing = SimpleNamespace(uid="workspace-1")
    with (
        patch.object(
            services.Workspace, "find_one", new=AsyncMock(return_value=existing)
        ) as find,
        pytest.raises(AlreadyExistsError) as exc,
    ):
        await services.find_or_create_workspace(
            tenant_id="tenant-1", name="Acme", slug="acme"
        )
    assert exc.value.error_code == "workspace_slug_exists"
    assert find.await_args.args[0]["slug"] == "acme"


def test_workspace_create_contract_has_slug_not_organization_code() -> None:
    item = WorkspaceSchema(tenant_id="tenant-1", name="Acme", slug="acme")
    assert item.slug == "acme"
    assert "slug" in WorkspaceSchema.model_fields
