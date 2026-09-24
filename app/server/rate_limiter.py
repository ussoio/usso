"""
Rate limiting configuration and utilities.

This module provides rate limiting functionality using pyrate_limiter with
optional Redis backing, configurable limits per endpoint, and fingerprint-based
identification.
"""

import hashlib
import logging
from collections.abc import Callable

import redis
from fastapi import Request, Response
from fastapi_limiter.callback import default_callback
from fastapi_limiter.depends import RateLimiter
from pyrate_limiter import Duration, Limiter, Rate, RedisBucket

from server.db import redis as redis_client
from utils.net import get_client_ip

logger = logging.getLogger(__name__)

# Rate limit constants (matching your existing configuration)
RATE_LIMIT_WINDOW = 60  # 1 minute window
MAX_REQUESTS = {
    "/auth": 10,  # 10 attempts per minute for all auth endpoints
    # "/auth/login": 5,  # 5 attempts per minute for login
    "/auth/magic-link": 0.2,  # 1 attempts per minute for magic link
    "/auth/request-magic-link": 0.1,  # 1 attempts per minute for magic link
    # "/auth/request-otp": 0.5,  # 1 attempts per minute for OTP
    "/auth/reset-password": 0.1,  # 1 attempts per minute for password reset
    "/auth/qr": 1,  # 10 attempts per minute for QR code generation
    "/auth/passkey": 5,  # 1 attempts per minute for passkey generation
    "/oauth/token": 10,
    "/agents/auth": 10,
    "/setup": 5,
    "/users/identifier-verification": 5,
    "/users/impersonation-otp": 5,
    "/kyc": 5,
    # "/captcha/challenge": 3,  # 3 attempts per minute for captcha challenge
    "default": 30,  # 60 requests per minute for other endpoints
}

_limiters: dict[tuple[int, int], Limiter] = {}


def _normalize_limit(path: str) -> tuple[int, int]:
    max_requests = MAX_REQUESTS.get(path, MAX_REQUESTS["default"])
    time_window = RATE_LIMIT_WINDOW

    if max_requests < 1:
        time_window = int(time_window / max_requests)
        max_requests = 1

    return max_requests, time_window


async def init_rate_limiter() -> None:
    """Initialize shared Redis-backed limiters for each unique rate configuration."""
    unique_configs = {_normalize_limit(path) for path in MAX_REQUESTS}
    unique_configs.add(_normalize_limit("default"))

    for max_requests, time_window in unique_configs:
        config = (max_requests, time_window)
        if config in _limiters:
            continue

        rate = Rate(max_requests, Duration.SECOND * time_window)
        if redis_client is None:
            _limiters[config] = Limiter(rate)
            continue

        bucket_key = f"usso-rate-limit:{max_requests}:{time_window}"
        try:
            bucket = await RedisBucket.init([rate], redis_client, bucket_key)
            _limiters[config] = Limiter(bucket)
        except Exception as e:
            logger.exception(
                "Failed to initialize Redis rate limiter for %s; "
                "using in-memory fallback",
                config,
            )
            if isinstance(e, redis.exceptions.NoScriptError):
                raise
            _limiters[config] = Limiter(rate)


async def reset_rate_limiters() -> None:
    """Clear and reinitialize rate limiters (for tests)."""
    _limiters.clear()
    await init_rate_limiter()


def generate_fingerprint(request: Request) -> str:
    """
    Generate a unique fingerprint for rate limiting identification.

    Uses only tenant host and trusted client IP resolution. Client-controlled
    headers such as User-Agent/fingerprint and cookies are deliberately ignored.

    Args:
        request: The FastAPI request object.

    Returns:
        SHA256 hash string representing the request fingerprint.

    """
    client_ip = get_client_ip(request) or ""

    url = getattr(request, "url", None)
    hostname = getattr(url, "hostname", "")
    raw: str = ":".join([
        hostname if isinstance(hostname, str) else "",
        client_ip,
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


def get_identifier(path: str, auth_required: bool) -> Callable[[Request], str]:
    """
    Create an identifier function for rate limiting.

    Args:
        path: The API path being rate limited.
        auth_required: Whether authentication is required for this endpoint.

    Returns:
        Async function that generates a unique identifier combining path,
        user ID (if authenticated), and fingerprint.

    """

    async def identifier(request: Request) -> str:  # ruff:ignore[unused-async]
        user_id = getattr(request.state, "user_id", None)
        key = user_id if (auth_required and user_id) else "-"
        fingerprint = generate_fingerprint(request)
        return f"{path}:{key}:{fingerprint}"

    return identifier


class PathRateLimiter(RateLimiter):
    """Rate limiter that avoids FastAPI nested-router route lookup issues."""

    def __init__(
        self,
        *,
        path: str,
        auth_required: bool,
        max_requests: int,
        time_window: int,
    ) -> None:
        """Initialize a path-scoped rate limiter."""
        self._config = (max_requests, time_window)
        self._fallback_rate = Rate(max_requests, Duration.SECOND * time_window)
        super().__init__(
            limiter=_limiters.get(self._config) or Limiter(self._fallback_rate),
            identifier=get_identifier(path, auth_required),
            callback=default_callback,
            blocking=False,
        )

    def _resolve_limiter(self) -> Limiter:
        limiter = _limiters.get(self._config)
        if limiter is None:
            limiter = Limiter(self._fallback_rate)
            _limiters[self._config] = limiter
        return limiter

    async def __call__(self, request: Request, response: Response) -> None:
        """Enforce the configured rate limit for the request path."""
        rate_key = await self.identifier(request)
        success = await self._resolve_limiter().try_acquire_async(
            rate_key,
            blocking=self.blocking,
        )

        if not success:
            return await self.callback(request, response)


def get_rate_limiter(path: str, auth_required: bool = False) -> PathRateLimiter:
    """
    Get a rate limiter instance for a specific path.

    Creates a RateLimiter configured with the appropriate limits for the
    given path. If max_requests is less than 1, adjusts the time window
    to achieve the desired rate.

    Args:
        path: The API path to rate limit.
        auth_required: Whether authentication is required for this endpoint.

    Returns:
        Configured RateLimiter instance for the specified path.

    """
    max_requests, time_window = _normalize_limit(path)

    return PathRateLimiter(
        path=path,
        auth_required=auth_required,
        max_requests=max_requests,
        time_window=time_window,
    )
