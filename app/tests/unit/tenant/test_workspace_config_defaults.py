"""Regression tests for WorkspaceConfig defaults."""

from apps.tenant.config import WorkspaceConfig


def test_workspace_config_defaults_enable_workspace_without_provider() -> None:
    config = WorkspaceConfig()
    assert config.enabled is True
    assert config.personal_workspace_active_by_default is True
    assert config.allow_member_create is True
    assert config.user_search_enabled is False
    assert "require_ceo_verification" not in WorkspaceConfig.model_fields
