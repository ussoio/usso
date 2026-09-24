"""Basic authentication utilities."""

import re

from starlette.datastructures import URL

from apps.tenant.models import Tenant


def get_tenant_url(tenant: Tenant, url: URL | str | None = None) -> str:
    """Get tenant URL."""
    if url:
        if isinstance(url, str):
            url = URL(url)
        scheme = "https" if "localhost" not in url.netloc else url.scheme
        url = f"{scheme}://{url.netloc}"
    else:
        url = tenant.primary_url
    return url


def sanitize_origin(origin: str | None) -> str | None:
    """Sanitize origin to prevent JavaScript injection and other security issues."""
    if not origin:
        return None

    # Remove protocol prefixes
    origin = origin.removeprefix("https://").removeprefix("http://")

    # Block dangerous protocols (case-insensitive)
    dangerous_protocols = ["javascript:", "data:", "vbscript:", "file:", "about:"]
    origin_lower = origin.lower()
    for protocol in dangerous_protocols:
        if origin_lower.startswith(protocol):
            return None

    # Only allow valid hostname characters:
    #    alphanumeric, dots, hyphens, colons (for ports)
    # This regex allows: domain.com, subdomain.domain.com, localhost,
    # 127.0.0.1, domain.com:8080
    # Pattern: starts with alphanumeric, optionally followed by
    # alphanumeric/dot/hyphen (ending with alphanumeric
    #    :port
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:[0-9]+)?$"
    if not re.match(pattern, origin):
        return None

    return origin
