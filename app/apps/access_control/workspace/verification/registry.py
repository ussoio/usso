"""Registry for workspace verification plugins."""

from __future__ import annotations

from apps.access_control.workspace.verification.base import AbstractWorkspaceVerifier
from server.exceptions import BadRequestError

_VERIFIERS: dict[str, AbstractWorkspaceVerifier] = {}
_BUILTINS_LOADED = False


def register(verifier: AbstractWorkspaceVerifier) -> AbstractWorkspaceVerifier:
    """Register a verifier instance by its ``name``."""
    if not verifier.name:
        raise ValueError("Workspace verifier must define a non-empty name")
    _VERIFIERS[verifier.name] = verifier
    return verifier


def ensure_builtins_loaded() -> None:
    """Mark the registry ready. Core ships with no built-in verifiers."""
    global _BUILTINS_LOADED
    _BUILTINS_LOADED = True


def get_verifier(name: str) -> AbstractWorkspaceVerifier:
    """Return a registered verifier or raise when the provider is unknown."""
    ensure_builtins_loaded()
    verifier = _VERIFIERS.get(name)
    if verifier is None:
        raise BadRequestError(
            error_code="workspace_verification_provider_unknown",
            detail=f"Unknown workspace verification provider: {name}",
            message={
                "en": f"Unknown workspace verification provider: {name}",
                "fa": "ارائه‌دهندهٔ تأیید فضای کاری ناشناخته است.",
            },
        )
    return verifier


def clear_registry() -> None:
    """Remove all registered verifiers (tests only)."""
    global _BUILTINS_LOADED
    _VERIFIERS.clear()
    _BUILTINS_LOADED = False


def registered_names() -> frozenset[str]:
    """Return names of currently registered verifiers."""
    ensure_builtins_loaded()
    return frozenset(_VERIFIERS)
