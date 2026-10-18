"""Drop expected client errors and shutdown cancellation from Sentry events."""

from __future__ import annotations

import asyncio
import re
import urllib.parse

from sentry_sdk.types import Event, Hint

_INSTALLED = False
_CLIENT_ERROR_CODES = {400, 401, 422}
_DROP_EXCEPTION_TYPES = {
    "UnauthorizedError",
    "BadRequestError",
    "RequestValidationError",
    "USSOError",
    "USSOException",
    "ValidationError",
}
_NO_TOKEN_PROVIDED = "No token provided"
_DROP_MESSAGE_PHRASES = ("request_validation_exception", "Refresh token required")
_URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+")


def _remove_url_query(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        parsed = urllib.parse.urlsplit(match.group(0))
        return urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            "",
        ))

    return _URL_PATTERN.sub(replace, value)


def scrub_sensitive_request_data(event: Event, hint: Hint) -> Event:
    """Remove query strings and request bodies before Sentry transport."""
    request = event.get("request")
    if isinstance(request, dict):
        url = request.get("url")
        if isinstance(url, str):
            request["url"] = _remove_url_query(url)
        request.pop("query_string", None)
        request.pop("data", None)
    exception = event.get("exception")
    if isinstance(exception, dict):
        for value in exception.get("values") or []:
            if isinstance(value, dict) and isinstance(value.get("value"), str):
                value["value"] = _remove_url_query(value["value"])
    return event


def _status_code(exc: BaseException | None) -> int | None:
    """Return an HTTP status code attached to an exception, if any."""
    if exc is None:
        return None
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    response_status = getattr(response, "status_code", None)
    if isinstance(response_status, int):
        return response_status
    return None


def _exception_from_hint(hint: Hint | None) -> BaseException | None:
    """Extract the original exception from a Sentry event hint."""
    if not hint:
        return None
    exc_info = hint.get("exc_info")
    if isinstance(exc_info, tuple) and len(exc_info) >= 2:
        exc = exc_info[1]
        if isinstance(exc, BaseException):
            return exc
    log_record = hint.get("log_record")
    log_exc_info = getattr(log_record, "exc_info", None)
    if isinstance(log_exc_info, tuple) and len(log_exc_info) >= 2:
        exc = log_exc_info[1]
        if isinstance(exc, BaseException):
            return exc
    return None


def _event_message_text(event: Event) -> str:
    """Collect the human-readable message strings attached to an event."""
    parts: list[str] = []
    message = event.get("message")
    if isinstance(message, str):
        parts.append(message)
    elif isinstance(message, dict):
        value = message.get("message")
        if isinstance(value, str):
            parts.append(value)
    logentry = event.get("logentry")
    if isinstance(logentry, dict):
        value = logentry.get("message")
        if isinstance(value, str):
            parts.append(value)
    return "\n".join(parts)


def _exception_values_match(event: Event) -> bool:
    """Scan serialized exception values for dropped types or client-error text."""
    for value in (event.get("exception") or {}).get("values") or []:
        if not isinstance(value, dict):
            continue
        type_name = str(value.get("type") or "")
        if type_name in _DROP_EXCEPTION_TYPES:
            return True
        text = f"{type_name} {value.get('value') or ''}"
        if _NO_TOKEN_PROVIDED in text:
            return True
        if any(phrase in text for phrase in _DROP_MESSAGE_PHRASES):
            return True
    return False


def event_is_client_error(event: Event, hint: Hint | None) -> bool:
    """Return True when this Sentry event is an expected client error (4xx)."""
    seen: set[int] = set()
    exc = _exception_from_hint(hint)
    while isinstance(exc, BaseException) and id(exc) not in seen:
        seen.add(id(exc))
        if _status_code(exc) in _CLIENT_ERROR_CODES:
            return True
        exc = exc.__cause__ or exc.__context__
    text = _event_message_text(event)
    if _exception_values_match(event):
        return True
    if _NO_TOKEN_PROVIDED in text:
        return True
    if any(phrase in text for phrase in _DROP_MESSAGE_PHRASES):
        return True
    if event.get("logger") == "usso":
        return text.startswith("Unauthorized") or _NO_TOKEN_PROVIDED in text
    return False


def drop_client_error_event(event: Event, hint: Hint) -> Event | None:
    """Sentry event processor: drop expected client errors, keep everything else."""
    if event_is_client_error(event, hint):
        return None
    return event


def _lifespan_event_text(event: Event) -> str:
    """Collect an event's message, log entry, exception and frame names."""
    parts: list[str] = []
    message = event.get("message")
    if isinstance(message, str):
        parts.append(message)
    logentry = event.get("logentry")
    if isinstance(logentry, dict):
        parts.extend(
            logentry[key]
            for key in ("message", "formatted")
            if isinstance(logentry.get(key), str)
        )
    exception = event.get("exception")
    values = exception.get("values") if isinstance(exception, dict) else None
    for value in values or []:
        if not isinstance(value, dict):
            continue
        parts.append(f"{value.get('type') or ''} {value.get('value') or ''}")
        stacktrace = value.get("stacktrace")
        frames = stacktrace.get("frames") if isinstance(stacktrace, dict) else None
        parts.extend(
            str(frame.get("function") or "")
            for frame in frames or []
            if isinstance(frame, dict)
        )
    return " ".join(parts)


def event_is_lifespan_shutdown_cancel(event: Event, hint: Hint | None) -> bool:
    """
    Identify cancellation logged by uvicorn/starlette during ASGI shutdown.

    Both the cancellation and ASGI lifespan context must be present. Keep
    request cancellation and real errors that merely mention "lifespan".
    """
    cancelled = False
    seen: set[int] = set()
    exc = _exception_from_hint(hint)
    while isinstance(exc, BaseException) and id(exc) not in seen:
        seen.add(id(exc))
        cancelled = cancelled or isinstance(exc, asyncio.CancelledError)
        exc = exc.__cause__ or exc.__context__
    text = _lifespan_event_text(event)
    cancelled = cancelled or "CancelledError" in text
    return cancelled and "lifespan" in text.lower()


def drop_lifespan_shutdown_event(event: Event, hint: Hint) -> Event | None:
    """Drop shutdown cancellation noise and preserve other Sentry events."""
    if event_is_lifespan_shutdown_cancel(event, hint):
        return None
    return event


def install_client_error_filter() -> bool:
    """Attach the client-error filter to the process-wide Sentry scope if active."""
    global _INSTALLED
    if _INSTALLED:
        return True
    try:
        import sentry_sdk
    except ImportError:
        return False
    client = sentry_sdk.get_client()
    if not client.is_active():
        return False
    sentry_sdk.get_global_scope().add_event_processor(scrub_sensitive_request_data)
    sentry_sdk.get_global_scope().add_event_processor(drop_client_error_event)
    sentry_sdk.get_global_scope().add_event_processor(drop_lifespan_shutdown_event)
    _INSTALLED = True
    return True
