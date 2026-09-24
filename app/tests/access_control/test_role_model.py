"""Tests for Role model: get_queryset workspace scoping."""

from apps.access_control.role.models import Role


class TestRoleGetQueryset:
    """Role.get_queryset with workspace_id and workspace_id_in."""

    def test_workspace_id_none_filters_tenant_wide(self) -> None:
        """When workspace_id is None, queryset filters for workspace_id is None."""
        q = Role.get_queryset(tenant_id="t1", workspace_id=None)
        assert "workspace_id" in q
        assert q["workspace_id"] is None
        assert "$or" not in q

    def test_workspace_id_set_uses_or(self) -> None:
        """When workspace_id is set, queryset uses $or for that workspace."""
        q = Role.get_queryset(tenant_id="t1", workspace_id="ws1")
        assert "$or" in q
        assert q["$or"] == [{"workspace_id": "ws1"}]
        assert "workspace_id" not in q or q.get("workspace_id") != "ws1"

    def test_workspace_id_in_builds_or_conditions(self) -> None:
        """When workspace_id_in is set, queryset has $or with each value."""
        q = Role.get_queryset(
            tenant_id="t1",
            workspace_id_in=[None, "ws1", "ws2"],
        )
        assert "$or" in q
        assert {"workspace_id": None} in q["$or"]
        assert {"workspace_id": "ws1"} in q["$or"]
        assert {"workspace_id": "ws2"} in q["$or"]
        assert len(q["$or"]) == 3

    def test_workspace_id_in_empty_list_no_or(self) -> None:
        """When workspace_id_in is empty, $or is not added (or_conditions empty)."""
        q = Role.get_queryset(tenant_id="t1", workspace_id_in=[])
        # Implementation adds $or only if or_conditions is truthy
        assert "$or" not in q

    def test_workspace_id_in_single_none(self) -> None:
        """workspace_id_in with only None."""
        q = Role.get_queryset(tenant_id="t1", workspace_id_in=[None])
        assert "$or" in q
        assert q["$or"] == [{"workspace_id": None}]

    def test_kwargs_passed_to_super_except_workspace_keys(self) -> None:
        """workspace_id and workspace_id_in are popped; other kwargs go to super."""
        q = Role.get_queryset(tenant_id="t1", is_deleted=False, workspace_id=None)
        assert q["workspace_id"] is None
        # tenant_id / is_deleted are handled by base; we only assert our part
        assert "workspace_id" in q
