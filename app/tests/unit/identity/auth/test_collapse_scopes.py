"""Unit tests for overlapping scope collapse."""

from types import SimpleNamespace

from apps.identity.auth.services.token import (
    collapse_overlapping_scopes,
    expand_scope_templates,
)


def test_collapse_keeps_higher_privilege() -> None:
    """Read is dropped when manage covers the same path."""
    assert set(
        collapse_overlapping_scopes([
            "read:sso/users",
            "manage:sso/users",
            "read:finance/ipg/deposit",
        ])
    ) == {"manage:sso/users", "read:finance/ipg/deposit"}


def test_collapse_keeps_broader_path() -> None:
    """Narrower resource path is dropped when a wildcard covers it."""
    assert set(
        collapse_overlapping_scopes([
            "read:sso/users/profile",
            "read:sso/*/*",
        ])
    ) == {"read:sso/*/*"}


def test_collapse_keeps_unfiltered_over_filtered() -> None:
    """Filtered scope is dropped when an unfiltered broader scope exists."""
    assert set(
        collapse_overlapping_scopes([
            "read:sso/*/*?workspace_id=ws-1",
            "read:sso/*/*",
        ])
    ) == {"read:sso/*/*"}


def test_collapse_keeps_non_overlapping() -> None:
    """Different resources or filters that do not cover each other stay."""
    assert set(
        collapse_overlapping_scopes([
            "read:sso/*/*?workspace_id=ws-1",
            "read:sso/*/*?workspace_id=ws-2",
            "create:finance/ipg/*?workspace_id=ws-1",
        ])
    ) == {
        "read:sso/*/*?workspace_id=ws-1",
        "read:sso/*/*?workspace_id=ws-2",
        "create:finance/ipg/*?workspace_id=ws-1",
    }


def test_collapse_dedupes_exact_duplicates() -> None:
    """Exact duplicates are reduced to one entry."""
    assert collapse_overlapping_scopes([
        "read:sso/users",
        "read:sso/users",
        "read:sso/users",
    ]) == ["read:sso/users"]


def test_expand_scope_templates_collapses_after_render() -> None:
    """Template expansion collapses overlaps in the rendered list."""
    user = SimpleNamespace(
        uid="user-1",
        model_dump=lambda mode="json": {"uid": "user-1", "tenant_id": "t1"},
    )
    result = expand_scope_templates(
        [
            "read:sso/*/*?workspace_id={workspace_id}",
            "manage:sso/*/*?workspace_id={workspace_id}",
            "read:finance/ipg/*?workspace_id={workspace_id}",
        ],
        user=user,  # type: ignore[arg-type]
        workspace_id="ws-9",
    )
    assert set(result) == {
        "manage:sso/*/*?workspace_id=ws-9",
        "read:finance/ipg/*?workspace_id=ws-9",
    }
