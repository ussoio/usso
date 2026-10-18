"""
Request-scoped trace ID (``X-Trace-ID``) adapter, local to this repository.

Each service keeps its own copy of this adapter so the submodule stays
independently cloneable and deployable; there is no shared runtime package.
Behaviour must stay aligned with the other copies (same contract below).

Why this exists next to ``fastapi_mongo_base.utils.trace``: the library
middleware is HTTP-only, accepts any header value (log injection), is missing
from fastapi-mongo-base < 1.8 (saas pins 1.3.6), and the library's own task
webhook sender uses a bare ``httpx.AsyncClient`` that never carries the ID.

Contract:
  * Ingress (HTTP and WebSocket) accepts only a canonical UUID. Anything else
    is replaced by a fresh UUID7. Raw rejected input is never logged.
  * The ID is echoed in HTTP responses and in the WebSocket ``accept``.
  * The ID lives in a ``ContextVar`` (the library's one when it exists, so its
    JSON log formatter prints ``trace_id``). ``asyncio.create_task`` copies it.
  * Outbound ``httpx`` requests to internal hosts carry it (never overwritten
    when a caller sets the header). Third-party hosts never receive it.
  * Work that outlives the request (queued tasks, webhooks from providers,
    bot message lifecycle) stores it with ``stamp_meta`` and restores it with
    ``trace_scope``.
"""

from __future__ import annotations

import contextlib
import functools
import ipaddress
import logging
import os
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator, MutableMapping
from contextvars import ContextVar, Token
from typing import Any, cast

import httpx
from starlette.applications import Starlette
from starlette.types import Receive, Send

try:  # share the library variable so its JsonFormatter logs ``trace_id``
    from fastapi_mongo_base.utils.trace import request_trace_id as _current
except ImportError:  # fastapi-mongo-base < 1.8, or a service without it
    _current = ContextVar("request_trace_id", default=None)


TRACE_ID_HEADER = "X-Trace-ID"
META_KEY = "trace_id"
_HEADER_LOWER = TRACE_ID_HEADER.lower()
_HEADER_BYTES = _HEADER_LOWER.encode()
_MAX_RAW_LENGTH = 64
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_INTERNAL_DOMAINS: tuple[str, ...] = ()
_SENTINEL = "_usso_trace_installed"


def _logger() -> logging.Logger:
    """Return the module logger, re-enabled if ``dictConfig`` disabled it."""
    log = logging.getLogger(__name__)
    log.disabled = False  # disable_existing_loggers silences import-time loggers
    return log


def new_trace_id() -> str:
    """Return a new UUID7 (48-bit ms timestamp, version 7, RFC 9562 layout)."""
    millis = time.time_ns() // 1_000_000
    rand = secrets.randbits(74)
    value = (
        ((millis & (2**48 - 1)) << 80)
        | (0x7 << 76)
        | ((rand >> 62) << 64)
        | (0b10 << 62)
        | (rand & (2**62 - 1))
    )
    return str(uuid.UUID(int=value))


def sanitize_trace_id(raw: object) -> str | None:
    """Return the canonical lowercase UUID for ``raw``, or None when unusable."""
    if isinstance(raw, bytes):
        raw = raw.decode("latin-1")
    if not isinstance(raw, str) or len(raw) > _MAX_RAW_LENGTH:
        return None
    candidate = raw.strip().lower()
    return candidate if _UUID_RE.fullmatch(candidate) else None


def resolve_trace_id(raw: object) -> str:
    """Return a safe trace ID: ``raw`` when valid, else a new UUID7."""
    return sanitize_trace_id(raw) or new_trace_id()


def get_trace_id() -> str | None:
    """Return the active trace ID, if any."""
    return _current.get()


def trace_headers() -> dict[str, str]:
    """Return the header that propagates the active trace ID (maybe empty)."""
    trace_id = get_trace_id()
    return {TRACE_ID_HEADER: trace_id} if trace_id else {}


def bind_trace_id(raw: object = None) -> Token:
    """Bind ``raw`` (or a new UUID7) as the active ID. Reset with the token."""
    return _current.set(resolve_trace_id(raw))


def reset_trace_id(token: Token) -> None:
    """Undo ``bind_trace_id``."""
    _current.reset(token)


@contextlib.contextmanager
def trace_scope(stored: object = None) -> Iterator[str]:
    """
    Run a block under a trace ID.

    Uses ``stored`` when it is a valid ID (task metadata, webhook payload),
    otherwise keeps the active ID, otherwise mints a UUID7.
    """
    trace_id = sanitize_trace_id(stored) or get_trace_id() or new_trace_id()
    token = _current.set(trace_id)
    try:
        yield trace_id
    finally:
        _current.reset(token)


def stamp_meta(meta: MutableMapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a copy of ``meta`` carrying the active ID under ``trace_id``."""
    stamped = dict(meta or {})
    if sanitize_trace_id(stamped.get(META_KEY)) is None:
        trace_id = get_trace_id()
        if trace_id:
            stamped[META_KEY] = trace_id
        else:
            stamped.pop(META_KEY, None)
    return stamped


def adopt_trace_id(stored: object) -> str | None:
    """
    Switch the active ID to a stored one (provider webhooks that cannot send it).

    The request keeps echoing its ingress ID; the link is logged once so both
    IDs can be joined. Returns the adopted ID or None if ``stored`` is unusable.
    """
    adopted = sanitize_trace_id(stored)
    if adopted is None:
        return None
    ingress = get_trace_id()
    _current.set(adopted)
    if ingress and ingress != adopted:
        _logger().info("trace adopted: ingress=%s task=%s", ingress, adopted)
    return adopted


# --------------------------------------------------------------------- ASGI


def _raw_header(scope: MutableMapping[str, Any]) -> bytes | None:
    for key, value in scope.get("headers") or ():
        if key.lower() == _HEADER_BYTES:
            return value
    return None


class TraceMiddleware:
    """
    Pure ASGI middleware for ``http`` and ``websocket`` scopes.

    Sanitises the inbound header (also rewriting it in the scope so inner
    middleware agrees), binds the ID, stores it on ``scope["state"]`` and adds
    it to ``http.response.start`` / ``websocket.accept``. A WebSocket closed
    before ``accept`` cannot carry headers (ASGI limitation); the rejection is
    logged with the ID instead.
    """

    def __init__(self, app: Callable[..., Any]) -> None:
        """Wrap ``app``."""
        self.app = app

    async def __call__(
        self, scope: MutableMapping[str, Any], receive: Receive, send: Send
    ) -> None:
        """Handle one ASGI connection."""
        kind = scope["type"]
        if kind not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        raw = _raw_header(scope)
        trace_id = sanitize_trace_id(raw)
        if trace_id is None:
            trace_id = new_trace_id()
            if raw is not None:
                _logger().warning(
                    "inbound %s replaced: invalid value (length=%d)",
                    TRACE_ID_HEADER,
                    len(raw),
                )
        encoded = trace_id.encode()
        scope["headers"] = [
            (k, v)
            for k, v in (scope.get("headers") or ())
            if k.lower() != _HEADER_BYTES
        ] + [(_HEADER_BYTES, encoded)]
        scope.setdefault("state", {})["trace_id"] = trace_id

        accepted = False

        async def traced_send(message: MutableMapping[str, Any]) -> None:
            nonlocal accepted
            kind_ = message["type"]
            if kind_ == "websocket.accept":
                accepted = True
            elif kind_ == "websocket.close" and not accepted:
                _logger().info(
                    "websocket handshake rejected (code=%s)", message.get("code", 1000)
                )
            if kind_ in {
                "http.response.start",
                "websocket.accept",
                "websocket.http.response.start",
            }:
                headers = [
                    (k, v)
                    for k, v in message.get("headers") or ()
                    if bytes(k).lower() != _HEADER_BYTES
                ]
                headers.append((_HEADER_BYTES, encoded))
                message = {**message, "headers": headers}
            await send(message)

        token = _current.set(trace_id)
        try:
            await self.app(scope, receive, traced_send)
        except Exception as exc:
            if kind == "websocket":
                _logger().error("websocket failed: %s", type(exc).__name__)
            raise
        finally:
            _current.reset(token)


def install_tracing(app: Starlette) -> None:
    """
    Make ``TraceMiddleware`` the outermost layer of a Starlette/FastAPI app.

    Wrapping ``build_middleware_stack`` (instead of ``add_middleware``) keeps it
    outside Starlette's ``ServerErrorMiddleware`` so 500 responses are tagged
    too. Call once at import time, right after the app is created.
    """
    if getattr(app, _SENTINEL, False):
        return
    build = app.build_middleware_stack
    app.build_middleware_stack = lambda: TraceMiddleware(build())  # type: ignore[method-assign]
    setattr(app, _SENTINEL, True)
    install_httpx_propagation()
    install_log_record_trace_id()


# -------------------------------------------------------------------- httpx


def is_internal_host(host: str | None) -> bool:
    """
    Return True for hosts that may receive the ID.

    Internal means a single-label name (Docker service, ``localhost``), a
    private/loopback IP, or an explicitly configured
    suffix listed in ``TRACE_PROPAGATE_HOSTS`` (comma separated).
    """
    name = (host or "").lower().rstrip(".")
    if not name:
        return False
    if "." not in name:
        return True
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        extra = tuple(
            item.strip().lower()
            for item in os.getenv("TRACE_PROPAGATE_HOSTS", "").split(",")
            if item.strip()
        )
        return any(
            name == domain or name.endswith(f".{domain}")
            for domain in (*_INTERNAL_DOMAINS, *(h.lstrip(".") for h in extra))
        )
    return address.is_private or address.is_loopback


try:  # bind the real classes now: tests may later replace ``httpx.AsyncClient``
    from httpx import AsyncClient as _AsyncClient
    from httpx import Client as _Client
except ImportError:  # pragma: no cover
    _AsyncClient = _Client = None  # type: ignore[assignment,misc]


def _inject(request: httpx.Request) -> None:
    trace_id = get_trace_id()
    if (
        trace_id
        and _HEADER_LOWER not in request.headers
        and is_internal_host(request.url.host)
    ):
        request.headers[TRACE_ID_HEADER] = trace_id


def install_httpx_propagation() -> None:
    """
    Patch ``httpx.Client.send`` and ``httpx.AsyncClient.send`` (idempotent).

    One class-level hook covers every client in the process, including the
    ones inside libraries (fastapi-mongo-base webhooks, usso SDK).
    """
    if _AsyncClient is None or _Client is None:
        return
    if getattr(_AsyncClient.send, _SENTINEL, False):
        return

    original_async = _AsyncClient.send
    original_sync = _Client.send

    @functools.wraps(original_async)
    async def send_async(
        self: httpx.AsyncClient,
        request: httpx.Request,
        *args: object,
        **kwargs: object,
    ) -> httpx.Response:
        _inject(request)
        send = cast(Callable[..., Awaitable[httpx.Response]], original_async)
        return await send(self, request, *args, **kwargs)

    @functools.wraps(original_sync)
    def send_sync(
        self: httpx.Client,
        request: httpx.Request,
        *args: object,
        **kwargs: object,
    ) -> httpx.Response:
        _inject(request)
        send = cast(Callable[..., httpx.Response], original_sync)
        return send(self, request, *args, **kwargs)

    setattr(send_async, _SENTINEL, True)
    setattr(send_sync, _SENTINEL, True)
    _AsyncClient.send = send_async  # type: ignore[method-assign]
    _Client.send = send_sync  # type: ignore[method-assign]


# ------------------------------------------------------------------ logging


def install_log_record_trace_id() -> None:
    """Add ``record.trace_id`` to every log record (idempotent)."""
    factory = logging.getLogRecordFactory()
    if getattr(factory, _SENTINEL, False):
        return

    def record_factory(*args: object, **kwargs: object) -> logging.LogRecord:
        record = factory(*args, **kwargs)
        record.trace_id = get_trace_id() or "-"
        return record

    setattr(record_factory, _SENTINEL, True)
    logging.setLogRecordFactory(record_factory)


# Active as soon as the module is imported, so text formats that print
# ``{trace_id}`` never see a record without the attribute.
install_log_record_trace_id()
