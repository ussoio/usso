"""Safe request-context middleware."""

from collections.abc import Awaitable, Callable

import fastapi
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from utils.net import get_client_ip
from utils.request_context import client_ip_var, user_agent_var


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Store trusted client IP and User-Agent in context variables."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[fastapi.Response]],
    ) -> fastapi.Response:
        """Bind request metadata for the lifetime of one request."""
        ip_token = client_ip_var.set(get_client_ip(request))
        ua_token = user_agent_var.set(request.headers.get("user-agent"))
        try:
            return await call_next(request)
        finally:
            client_ip_var.reset(ip_token)
            user_agent_var.reset(ua_token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply browser hardening and prevent caching of authentication material."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[fastapi.Response]],
    ) -> fastapi.Response:
        """Attach security headers to every response."""
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        path = request.url.path
        if "/auth/" in path or "/oauth/" in path:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies, including chunked bodies."""

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        """Initialize the request-body limiter."""
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Enforce the configured byte limit for one ASGI request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = self.max_body_size + 1
        if content_length > self.max_body_size:
            await PlainTextResponse("Request body too large", status_code=413)(
                scope, receive, send
            )
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_size:
                    raise _RequestBodyTooLargeError
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestBodyTooLargeError:
            await PlainTextResponse("Request body too large", status_code=413)(
                scope, receive, send
            )


class _RequestBodyTooLargeError(Exception):
    """Internal short-circuit for chunked oversized bodies."""
