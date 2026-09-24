"""OAuth2/OIDC integration module for tenant management."""

from .oidc import router as integration_router
from .routes import router as oauth_router

__all__ = ["integration_router", "oauth_router"]
