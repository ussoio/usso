"""Network utilities."""

import ipaddress
import os
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Request
from IP2Location import IP2Location, database


def get_client_ip(request: Request) -> str | None:
    """Resolve the client by walking the trusted proxy chain from right to left."""
    client = getattr(request, "client", None)
    peer = getattr(client, "host", None)
    configured = os.getenv("TRUSTED_PROXY_NETWORKS", "")
    forwarded = request.headers.get("X-Forwarded-For", "")
    if not (peer and forwarded and configured):
        return peer

    try:
        peer_ip = ipaddress.ip_address(peer)
        networks = [
            ipaddress.ip_network(value.strip(), strict=False)
            for value in configured.split(",")
            if value.strip()
        ]
    except ValueError:
        return peer

    if not any(peer_ip in network for network in networks):
        return peer

    forwarded_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        forwarded_ips = [
            ipaddress.ip_address(value.strip())
            for value in forwarded.split(",")
            if value.strip()
        ]
    except ValueError:
        return peer

    for candidate in reversed(forwarded_ips):
        if not any(candidate in network for network in networks):
            return str(candidate)
    if forwarded_ips:
        return str(forwarded_ips[0])
    return peer


def get_client_user_agent(request: Request) -> str:
    """Return the client user agent from the request."""
    return request.headers.get("user-agent", "unknown")


def filter_not_detected(x: str) -> str | None:
    """Filter out 'not detected' values."""
    not_detected_message = " ".join([
        "This parameter is unavailable in selected .BIN data file.",
        "Please upgrade data file.",
    ])
    return None if x == not_detected_message else x


async def get_location_ipapi(
    ip_address: str,
) -> dict[str, str | float | None] | None:
    """Get location from IP using ipapi.co."""
    # return None   # ruff:ignore[commented-out-code]
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"https://ipapi.co/{ip_address}/json/",
                timeout=3,
            )
            response.raise_for_status()
            data: dict[str, str | float | None] = response.json()
            location_data = {
                "ip": ip_address,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country_name"),
                "location": ", ".join(
                    filter(
                        None,
                        [
                            data.get("country_name", ""),
                            data.get("region", ""),
                            data.get("city", ""),
                        ],
                    )
                ),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
            }
        except httpx.HTTPError:
            return None
        return location_data


def get_location_ip2location(
    ip_address: str,
) -> dict[str, str | float | None] | None:
    """Get location from IP using IP2Location database."""
    db = IP2Location(Path("statics") / "IP2LOCATION-LITE-DB1.IPV6.BIN")
    record: database.IP2LocationRecord = db.get_all(ip_address)
    location_data = {
        "ip": ip_address,
        "city": filter_not_detected(record.city),
        "region": filter_not_detected(record.region),
        "country": filter_not_detected(record.country_long),
        "location": ", ".join(
            filter(
                None,
                [
                    filter_not_detected(record.country_long),
                    filter_not_detected(record.region),
                    filter_not_detected(record.city),
                ],
            )
        ),
        "latitude": filter_not_detected(record.latitude),
        "longitude": filter_not_detected(record.longitude),
    }
    return location_data


async def get_location(
    ip_address: str,
    *,
    method: Literal["ipapi", "ip2location"] = "ip2location",
) -> dict[str, str | float | None] | None:
    """Get location from IP address using specified method."""
    if method == "ipapi":
        return await get_location_ipapi(ip_address)
    elif method == "ip2location":
        return get_location_ip2location(ip_address)

    raise ValueError(f"Invalid method: {method}")
