"""primary_url must normalize bare hosts and full URLs, including localhost."""

from types import SimpleNamespace

import pytest

from apps.tenant.schemas import TenantRetrieveSchema


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("localhost", "http://localhost:8000"),
        ("localhost:8000", "http://localhost:8000"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("https://sso.example.com", "https://sso.example.com"),
        ("sso.example.com", "https://sso.example.com"),
        ("http://localhost:8000/", "http://localhost:8000"),
    ],
)
def test_primary_url_normalizes_domain(domain: str, expected: str) -> None:
    tenant = SimpleNamespace(primary_domain=domain)
    assert TenantRetrieveSchema.primary_url.fget(tenant) == expected
