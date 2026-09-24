"""Debug-mode mocking for external service calls."""

import functools
import inspect
from collections.abc import Awaitable, Callable

from server.config import Settings


def _resolve_mock[R](
    mock_response: R | Callable[..., R | Awaitable[R]],
    *args: object,
    **kwargs: object,
) -> R | Awaitable[R]:
    if callable(mock_response):
        return mock_response(*args, **kwargs)
    return mock_response


def debug_mode_mock[R](
    mock_response: R | Callable[..., R | Awaitable[R]],
) -> Callable[[Callable[..., R | Awaitable[R]]], Callable[..., R | Awaitable[R]]]:
    """Return a mock response instead of calling the function when debug is enabled."""

    def decorator(
        func: Callable[..., R | Awaitable[R]],
    ) -> Callable[..., R | Awaitable[R]]:

        @functools.wraps(func)
        async def async_wrapper(*args: object, **kwargs: object) -> R:
            if Settings.debug:
                result = _resolve_mock(mock_response, *args, **kwargs)
                if isinstance(result, Awaitable):
                    return await result
                return result
            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: object, **kwargs: object) -> R:
            if Settings.debug:
                result = _resolve_mock(mock_response, *args, **kwargs)
                if isinstance(result, Awaitable):
                    msg = (
                        "debug_mode_mock callable returned Awaitable for sync function"
                    )
                    raise TypeError(msg)
                return result
            return func(*args, **kwargs)

        return async_wrapper if inspect.iscoroutinefunction(func) else sync_wrapper

    return decorator
