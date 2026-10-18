"""
FastAPI server configuration.

This module defines the Settings class that holds all application configuration
including database URIs, API keys, captcha settings, and logging configuration.
"""

import dataclasses
import os
from pathlib import Path

import dotenv
from fastapi_mongo_base.core import config

dotenv.load_dotenv()


def _required_secret(name: str) -> str:
    """Load a required secret and fail before the application starts."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    if len(value.encode()) < 32:
        raise RuntimeError(
            f"Required environment variable {name} must contain at least 32 bytes"
        )
    return value


@dataclasses.dataclass
class Settings(config.Settings):
    """
    Application settings and configuration.

    Extends the base Settings from fastapi_mongo_base with USSO-specific
    configuration including MongoDB, Redis, captcha, and system settings.

    Attributes:
        project_name: Name of the project/application.
        base_dir: Base directory path of the application.
        base_path: Base API path prefix for all routes.
        gateway_url: URL of the API gateway.
        mongo_uri: MongoDB connection URI.
        redis_uri: Redis connection URI.
        system_password: System-level password for administrative operations.
        captcha_key: Secret key for captcha generation.
        captcha_max_number: Maximum number for captcha challenges.
        captcha_verification_duration: Duration in seconds for captcha verification
                                       validity.
        captcha_max_usage_count: Maximum number of times a captcha can be used.
        sentry_dsn: Sentry DSN for error tracking (optional).

    """

    project_name: str = os.getenv("PROJECT_NAME")
    base_dir: Path = Path(__file__).resolve().parent.parent
    base_path: str = "/api/sso/v1"
    gateway_url: str = os.getenv(
        "GATEWAY_URL", getattr(config.Settings, "root_url", None)
    )

    mongo_uri: str = os.getenv("MONGO_URI", default="mongodb://localhost:27017/")
    redis_uri: str = os.getenv("REDIS_URI", default="redis://localhost:6379/")

    system_password: str = _required_secret("SYSTEM_PASSWORD")
    captcha_key: str = _required_secret("CAPTCHA_KEY")
    captcha_max_number: int = 100_000
    captcha_verification_duration: int = 60 * 60  # 1 hour
    captcha_max_usage_count: int = 5
    max_request_body_bytes: int = int(
        os.getenv("MAX_REQUEST_BODY_BYTES", str(1024 * 1024))
    )

    sentry_dsn: str | None = os.getenv("SENTRY_DSN")
    # Resource servers that tokens of openly
    # registered clients are also issued for, as extra ``aud`` values.
    dynamic_client_audiences: tuple[str, ...] = tuple(
        a.strip()
        for a in os.getenv("OAUTH_DYNAMIC_CLIENT_AUDIENCES", "").split(",")
        if a.strip()
    )

    @classmethod
    def get_log_config(cls, console_level: str = "INFO", **kwargs: object) -> dict:
        """
        Get logging configuration dictionary.

        Args:
            console_level: Logging level for console output.
            **kwargs: Additional keyword arguments (unused).

        Returns:
            Dictionary containing logging configuration for formatters,
            handlers, and loggers.

        """
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "[{levelname} {name} : {filename}:{lineno} : {asctime} -> {funcName:10}] [trace={trace_id}] {message}",  # ruff:ignore[line-too-long]
                    "style": "{",
                    "defaults": {"trace_id": "-"},
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": console_level,
                    "formatter": "standard",
                },
                "file": {
                    "class": "logging.FileHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "filename": "logs/app.log",
                },
            },
            "root": {
                "handlers": [
                    "console",
                    "file",
                ],
                "level": console_level,
            },
            "loggers": {
                "apps.identity.agent.routes": {
                    "handlers": [
                        "console",
                        "file",
                    ],
                    "level": console_level,
                    "propagate": True,
                },
            },
        }
        return log_config
