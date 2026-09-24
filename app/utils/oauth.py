"""
Abstract OAuth2 (client_credentials) + shared transport for sync/async services.

Design goals:
- One reusable OAuth core for mobject services (credentials are NOT shared).

- Supports both token styles:
  1) Basic Authorization header + form body (BMI-style)
  2) client_id/client_secret in form body (OAuth client_secret_post)
- Token cache respects expires_in, prevents stampede (locks), retries once on 401.
"""

import asyncio
import base64
import dataclasses
import logging
import threading
import time
from types import TracebackType
from typing import Literal, Self

import httpx

logger = logging.getLogger(__name__)

_SENSITIVE_KEY_PARTS = ("token", "secret", "password", "authorization", "api_key")


def _redact(value: object) -> object:
    """Redact common credential fields before structured error logging."""
    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if any(part in str(key).lower() for part in _SENSITIVE_KEY_PARTS)
                else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class APIError(RuntimeError):
    """HTTP/API error with optional payload."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        payload: object | None = None,
    ) -> None:
        """Initialize API error."""
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


def _json(resp: httpx.Response) -> dict[str, object]:
    """Parse JSON safely."""
    try:
        j = resp.json()
        return j if isinstance(j, dict) else {"_json": j}
    except Exception:
        return {"_raw": resp.text}


def _payload_or_error(
    resp: httpx.Response, raise_exception: bool = True
) -> dict[str, object]:
    """Raise APIError on non-2xx, include best-effort payload."""
    payload = _json(resp)
    if resp.is_error:
        logger.error(
            "API error: %s %s %s\n%s",
            resp.status_code,
            resp.request.method,
            resp.request.url,
            _redact(payload),
        )
        if raise_exception:
            raise APIError(
                f"HTTP {resp.status_code} {resp.request.method} {resp.request.url}",
                status_code=resp.status_code,
                payload=payload,
            )
    return payload


@dataclasses.dataclass(frozen=True)
class OAuthCreds:
    """OAuth client_credentials input (also used as cache key)."""

    token_url: str
    client_id: str
    client_secret: str
    scope: str | None = None
    style: Literal["basic", "form"] = "basic"


@dataclasses.dataclass
class _Token:
    """Token entry including access token and expiration time."""

    token: str
    expires_at: float

    def is_valid(self) -> bool:
        """Check if token is valid."""
        return self.expires_at > time.monotonic()


class TokenCache:
    """
    Shared token cache (process-wide or injected).

    - Key is OAuthCreds (frozen+hashable)
    - tokens never mix across creds/scope/style/url.
    - thread-safe + async-safe
    """

    def __init__(self, *, skew: int = 15) -> None:
        """Initialize token cache."""
        self._skew = skew
        self._store: dict[OAuthCreds, _Token] = {}
        self._lock = threading.Lock()
        self._alock = asyncio.Lock()

    def _is_valid(self, t: _Token | None) -> bool:
        """Check if token is valid."""
        return bool(t) and t.is_valid()

    def get(self, key: OAuthCreds) -> _Token | None:
        """Get token from cache."""
        t = self._store.get(key)
        return t if self._is_valid(t) else None

    def set(self, key: OAuthCreds, token: str, expires_in: object) -> _Token:
        """Set token in cache."""
        try:
            s = int(expires_in)
        except Exception:
            s = 600
        ttl = max(30, s - self._skew)
        t = _Token(token=token, expires_at=time.monotonic() + ttl)
        self._store[key] = t
        return t

    def invalidate(self, key: OAuthCreds) -> None:
        """Invalidate token in cache."""
        with self._lock:
            self._store.pop(key, None)

    async def ainvalidate(self, key: OAuthCreds) -> None:
        """Invalidate token in cache asynchronously."""
        async with self._alock:
            self._store.pop(key, None)

    @property
    def lock(self) -> threading.Lock:
        """Thread lock."""
        return self._lock

    @property
    def alock(self) -> asyncio.Lock:
        """Async lock."""
        return self._alock


_DEFAULT_TOKEN_CACHE = TokenCache(skew=15)


class BaseOAuthService:
    """
    Base OAuth service.

    Minimal, readable base:
    - fetches token (basic or form style)
    - caches token with expires_in in shared TokenCache
    - injects Bearer token into requests
    - retries once on 401 (invalidate + re-fetch)
    """

    def __init__(
        self,
        *,
        base_url: str,
        creds: OAuthCreds,
        timeout: float = 30.0,
        token_cache: TokenCache | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize base OAuth service."""
        self.base_url = base_url.rstrip("/")
        self.creds = creds
        self.timeout = timeout

        # shared cache (injectable)
        self._cache = token_cache or _DEFAULT_TOKEN_CACHE

        # sync/async clients
        self._sync = httpx.Client(base_url=self.base_url, timeout=timeout, **kwargs)
        self._async = httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, **kwargs
        )

    # --- lifecycle ---
    def close(self) -> None:
        """Close OAuth service."""
        self._sync.close()

    async def aclose(self) -> None:
        """Close OAuth service asynchronously."""
        await self._async.aclose()

    async def __aenter__(self) -> Self:
        """Enter OAuth service asynchronously."""
        return self

    async def __aexit__(
        self, exc_type: type | None, exc: Exception | None, tb: TracebackType | None
    ) -> None:
        """Exit OAuth service asynchronously."""
        await self._async.__aexit__(exc_type, exc, tb)

    # --- token plumbing ---
    def _cache_key(self) -> OAuthCreds:
        # creds is frozen+hashable; safe to use as-is.
        return self.creds

    def _build_token_request(self) -> tuple[dict[str, str], dict[str, str]]:
        """
        Build token request.

        Returns:
            tuple[dict[str, str], dict[str, str]]: Headers and data for token request.

        """
        creds = self.creds
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"grant_type": "client_credentials"}

        if creds.scope:
            data["scope"] = creds.scope

        match creds.style:
            case "basic":
                basic = base64.b64encode(
                    f"{creds.client_id}:{creds.client_secret}".encode()
                ).decode("ascii")
                headers["Authorization"] = f"Basic {basic}"
            case "form":
                data["client_id"] = creds.client_id
                data["client_secret"] = creds.client_secret
            case _:
                raise ValueError("Unknown OAuth style. Use 'basic' or 'form'.")

        return headers, data

    def _extract_access_token(self, payload: dict[str, object]) -> tuple[str, object]:
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise APIError("Auth response missing access_token", payload=payload)
        return token, payload.get("expires_in", 600)

    def _request_token(self) -> dict[str, object]:
        headers, data = self._build_token_request()
        r = self._sync.post(self.creds.token_url, headers=headers, data=data)
        return _payload_or_error(r)

    async def _arequest_token(self) -> dict[str, object]:
        headers, data = self._build_token_request()
        r = await self._async.post(self.creds.token_url, headers=headers, data=data)
        return _payload_or_error(r)

    def _get_token(self) -> str:
        key = self._cache_key()
        cached = self._cache.get(key)
        if cached:
            return cached.token

        with self._cache.lock:
            cached = self._cache.get(key)
            if cached:
                return cached.token

            payload = self._request_token()
            token, expires_in = self._extract_access_token(payload)
            token_object = self._cache.set(key, token, expires_in)
            return token_object.token

    async def _aget_token(self) -> str:
        key = self._cache_key()
        cached = self._cache.get(key)
        if cached:
            return cached.token

        async with self._cache.alock:
            cached = self._cache.get(key)
            if cached:
                return cached.token

            payload = await self._arequest_token()
            token, expires_in = self._extract_access_token(payload)
            token_object = self._cache.set(key, token, expires_in)
            return token_object.token

    def _invalidate_token(self) -> None:
        key = self._cache_key()
        self._cache.invalidate(key)

    async def _ainvalidate_token(self) -> None:
        key = self._cache_key()
        await self._cache.ainvalidate(key)

    # --- request helpers ---
    def _request(
        self,
        method: str,
        url: str,
        *,
        json: dict | None = None,
        headers: dict | None = None,
    ) -> dict[str, object]:
        token = self._get_token()
        hdrs = dict(headers or {})
        hdrs["Authorization"] = f"Bearer {token}"

        resp = self._sync.request(method, url, json=json, headers=hdrs)
        if resp.status_code == 401:
            self._invalidate_token()
            token2 = self._get_token()
            hdrs["Authorization"] = f"Bearer {token2}"
            resp = self._sync.request(method, url, json=json, headers=hdrs)

        return _payload_or_error(resp)

    async def _arequest(
        self,
        method: str,
        url: str,
        *,
        json: dict | None = None,
        headers: dict | None = None,
        raise_exception: bool = True,
    ) -> dict[str, object]:
        token = await self._aget_token()
        hdrs = dict(headers or {})
        hdrs["Authorization"] = f"Bearer {token}"

        resp = await self._async.request(method, url, json=json, headers=hdrs)
        if resp.status_code == 401:
            await self._ainvalidate_token()
            token2 = await self._aget_token()
            hdrs["Authorization"] = f"Bearer {token2}"
            resp = await self._async.request(method, url, json=json, headers=hdrs)

        return _payload_or_error(resp, raise_exception=raise_exception)
