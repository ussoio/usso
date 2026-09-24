"""Application HTTP exceptions extending fastapi_mongo_base resource errors."""

from __future__ import annotations

from fastapi_mongo_base.errors import (
    AlreadyExistsError,
    BadRequestError,
    BaseHTTPException,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    PaymentRequiredError,
    ResourceLockedError,
    UnauthorizedError,
)

__all__ = [
    "AlreadyExistsError",
    "BadRequestError",
    "ConflictError",
    "FeatureNotImplementedError",
    "ForbiddenError",
    "NotFoundError",
    "PaymentRequiredError",
    "ResourceLockedError",
    "UnauthorizedError",
]


class TooManyRequestsError(BaseHTTPException):
    """Raised when a request is made too many times."""

    status_code = 429
    error_code = "too_many_requests"
    message_en = "Too many requests"
    message_fa = "درخواست‌های همزمان زیادی ارسال شده است."


class FeatureNotImplementedError(BaseHTTPException):
    """Raised when a requested feature is not implemented (HTTP 501)."""

    status_code = 501
    error_code = "not_implemented"
    message_en = "Not implemented"
    message_fa = "این قابلیت هنوز فعال نشده است."


class ServiceError(BaseHTTPException):
    """Raised when a service error occurs (HTTP 500)."""

    status_code = 500
    error_code = "service_error"
    message_en = "Service error"
    message_fa = "خطای سرویس رخ داده است."


class ServiceUnavailableError(BaseHTTPException):
    """Raised when a service is unavailable."""

    status_code = 503
    error_code = "service_unavailable"
    message_en = "Service unavailable"
    message_fa = "سرویس در دسترس نیست."
