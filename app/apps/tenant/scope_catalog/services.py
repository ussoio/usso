"""Business logic for syncing and reading the scope catalog."""

from __future__ import annotations

from usso.authorization import parse_scope

from . import models, schemas


def parse_scope_fields(scope: str) -> tuple[str | None, str | None]:
    """Derive action and resource_path from a scope string."""
    action, path_parts, _filters = parse_scope(scope)
    resource_path = "/".join(path_parts) if path_parts else None
    return (action or None), resource_path


def normalize_service_name(service: str) -> str:
    """Normalize a service slug for catalog keys."""
    return service.strip().lower()


async def sync_service_scopes(
    *,
    tenant_id: str,
    service: str,
    items: list[schemas.ScopeCatalogItemIn],
) -> list[models.ScopeCatalog]:
    """
    Replace service-sourced catalog rows for one service.

    Manual entries for the same service are preserved. Soft-deleted service
    rows are revived when the scope reappears in the payload.
    """
    service_name = normalize_service_name(service)
    incoming = {item.scope: item for item in items}

    existing = await models.ScopeCatalog.find({
        "tenant_id": tenant_id,
        "service": service_name,
        "is_deleted": False,
    }).to_list()

    by_scope = {entry.scope: entry for entry in existing}
    result: list[models.ScopeCatalog] = []

    for entry in existing:
        if entry.source == schemas.ScopeCatalogSource.MANUAL:
            result.append(entry)
            continue
        if entry.scope not in incoming:
            await models.ScopeCatalog.delete_item(entry)

    for scope, item in incoming.items():
        current = by_scope.get(scope)
        if current is not None and current.source == schemas.ScopeCatalogSource.MANUAL:
            continue

        action, resource_path = parse_scope_fields(scope)
        update_payload = {
            "service": service_name,
            "scope": scope,
            "action": action,
            "resource_path": resource_path,
            "label": item.label,
            "label_fa": item.label_fa,
            "description": item.description,
            "source": schemas.ScopeCatalogSource.SERVICE,
            "is_deleted": False,
        }

        if current is not None:
            updated = await models.ScopeCatalog.update_item(current, update_payload)
            result.append(updated)
            continue

        deleted = await models.ScopeCatalog.find_one({
            "tenant_id": tenant_id,
            "service": service_name,
            "scope": scope,
            "is_deleted": True,
        })
        if deleted is not None:
            revived = await models.ScopeCatalog.update_item(deleted, update_payload)
            result.append(revived)
            continue

        created = await models.ScopeCatalog.create_item({
            "tenant_id": tenant_id,
            **update_payload,
        })
        result.append(created)

    result.sort(key=lambda row: (row.service, row.scope))
    return result


async def create_manual_entry(
    *,
    tenant_id: str,
    data: schemas.ScopeCatalogCreateSchema,
) -> models.ScopeCatalog:
    """Create a manually curated catalog entry."""
    action, resource_path = parse_scope_fields(data.scope)
    return await models.ScopeCatalog.create_item({
        "tenant_id": tenant_id,
        "service": data.service,
        "scope": data.scope,
        "action": action,
        "resource_path": resource_path,
        "label": data.label,
        "label_fa": data.label_fa,
        "description": data.description,
        "source": schemas.ScopeCatalogSource.MANUAL,
    })
