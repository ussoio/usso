"""Validation helpers for server-side outbound HTTP requests."""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit


class UnsafeOutboundURLError(ValueError):
    """Raised when an outbound URL could reach a non-public destination."""


def _parsed_public_url(url: str, *, allow_http: bool = False) -> tuple[str, int]:
    parsed = urlsplit(url)
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed_schemes or not parsed.hostname:
        raise UnsafeOutboundURLError("Outbound URL must use HTTPS")
    if parsed.username or parsed.password:
        raise UnsafeOutboundURLError("Outbound URL must not contain credentials")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise UnsafeOutboundURLError("Outbound URL has an invalid port") from exc
    return parsed.hostname, port


def _assert_public_ip(address: str) -> None:
    ip = ipaddress.ip_address(address)
    if not ip.is_global:
        raise UnsafeOutboundURLError("Outbound URL resolves to a non-public address")


def validate_public_url_sync(url: str, *, allow_http: bool = False) -> str:
    """Resolve and reject loopback/private/link-local/reserved HTTP targets."""
    hostname, port = _parsed_public_url(url, allow_http=allow_http)
    try:
        _assert_public_ip(hostname)
    except ValueError:
        try:
            addresses = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise UnsafeOutboundURLError(
                "Outbound hostname could not be resolved"
            ) from exc
        if not addresses:
            raise UnsafeOutboundURLError(
                "Outbound hostname could not be resolved"
            ) from None
        for address in addresses:
            _assert_public_ip(address[4][0])
    return url


async def validate_public_url(url: str, *, allow_http: bool = False) -> str:
    """Async wrapper for public outbound URL validation."""
    return await asyncio.to_thread(
        validate_public_url_sync,
        url,
        allow_http=allow_http,
    )
