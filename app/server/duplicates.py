"""Map unique-index violations on accounts to one account-exists error."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_mongo_base.errors.handlers import (
    base_http_exception_handler,
    mongodb_exception_handler,
)
from pymongo.errors import DuplicateKeyError

from .exceptions import AccountAlreadyExistsError

if TYPE_CHECKING:
    from fastapi import Request
    from fastapi.responses import JSONResponse

# Unique keys that identify a person (UserIdentifier and User indexes).
_ACCOUNT_KEYS = frozenset({"identifier", "username", "phone", "email", "national_id"})


def duplicate_key_handler(request: Request, exc: Exception) -> JSONResponse:
    """Answer duplicate person keys with the shared account message."""
    if not isinstance(exc, DuplicateKeyError):
        raise exc
    key_pattern = (exc.details or {}).get("keyPattern") or {}
    if _ACCOUNT_KEYS & set(key_pattern):
        return base_http_exception_handler(request, AccountAlreadyExistsError())
    return mongodb_exception_handler(request, exc)
