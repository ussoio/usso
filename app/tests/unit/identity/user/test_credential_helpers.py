"""Unit tests for credential helper utilities."""

from apps.identity.user.credential_services import get_rp_id


def test_get_rp_id_strips_port_and_falls_back() -> None:
    """Hostname port is stripped; tenant domain is used as fallback."""
    assert get_rp_id("sso.example.test:8443") == "sso.example.test"
    assert get_rp_id(None, "tenant.example.test") == "tenant.example.test"
    assert get_rp_id("plain.example.test") == "plain.example.test"
