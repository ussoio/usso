"""Unit tests for rate limiter helpers."""

from server import rate_limiter


def test_normalize_limit_default_and_fractional() -> None:
    """Fractional max_requests expand the time window to one request."""
    assert rate_limiter._normalize_limit("default") == (30, 60)
    assert rate_limiter._normalize_limit("/auth/qr") == (1, 60)
    # 0.1 req/min => 1 request per 600 seconds
    assert rate_limiter._normalize_limit("/auth/reset-password") == (1, 600)
    assert rate_limiter._normalize_limit("/auth/magic-link") == (1, 300)
