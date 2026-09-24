"""Pluggable KYC provider interface (SSO core)."""

from __future__ import annotations

from typing import Any, Protocol


class KycProvider(Protocol):
    """External identity verification backend."""

    async def verify_phone(self, national_code: str, phone: str) -> bool:
        """Return whether phone ownership matches the national code."""

    async def verify_civil(
        self, national_code: str, birth_date_shamsi: str
    ) -> dict[str, Any]:
        """Return civil-registry data for the national code, or raise on failure."""

    async def init_kyc(self, national_code: str, phone: str) -> dict[str, Any]:
        """Start an external KYC session (direct or redirect-style)."""

    async def verify_kyc(self, kyc_id: str) -> bool:
        """Return whether an external KYC session completed successfully."""


class NoopKycProvider:
    """Default provider: always succeeds without calling external services."""

    async def verify_phone(self, national_code: str, phone: str) -> bool:
        """Return success without contacting a phone-verification service."""
        return True

    async def verify_civil(
        self, national_code: str, birth_date_shamsi: str
    ) -> dict[str, Any]:
        """Return empty civil-registry data."""
        return {}

    async def init_kyc(self, national_code: str, phone: str) -> dict[str, Any]:
        """Return an empty KYC session payload."""
        return {}

    async def verify_kyc(self, kyc_id: str) -> bool:
        """Return success without contacting an external KYC service."""
        return True


_provider: KycProvider = NoopKycProvider()


def get_kyc_provider() -> KycProvider:
    """Return the active KYC provider."""
    return _provider


def set_kyc_provider(provider: KycProvider) -> None:
    """Replace the active KYC provider (deployment overlays / tests)."""
    global _provider
    _provider = provider
