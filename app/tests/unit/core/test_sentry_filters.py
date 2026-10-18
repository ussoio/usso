"""Tests for dropping expected HTTP 400/401 client-error events before Sentry."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from utils.sentry_filters import (
    drop_client_error_event,
    drop_lifespan_shutdown_event,
    event_is_client_error,
    event_is_lifespan_shutdown_cancel,
    install_client_error_filter,
)


class _StubError(Exception):
    """Exception carrying an optional HTTP status and/or response object."""

    def __init__(
        self,
        status_code: int | None = None,
        response: object | None = None,
        message: str = "stub error",
    ) -> None:
        self.status_code = status_code
        self.response = response
        super().__init__(message)


def _hint(exc: BaseException | None) -> dict:
    if exc is None:
        return {}
    return {"exc_info": (type(exc), exc, None)}


def test_drops_http_401() -> None:
    exc = _StubError(status_code=401)
    event = {"ok": True}
    assert event_is_client_error(event, _hint(exc)) is True
    assert drop_client_error_event(event, _hint(exc)) is None


def test_drops_http_400() -> None:
    exc = _StubError(status_code=400)
    assert event_is_client_error({"ok": True}, _hint(exc)) is True


def test_drops_status_from_response_attribute() -> None:
    exc = _StubError(response=SimpleNamespace(status_code=401))
    assert event_is_client_error({"ok": True}, _hint(exc)) is True


def test_keeps_http_500() -> None:
    exc = _StubError(status_code=500)
    event = {"ok": True}
    assert event_is_client_error(event, _hint(exc)) is False
    assert drop_client_error_event(event, _hint(exc)) is event


def test_keeps_http_503() -> None:
    exc = _StubError(status_code=503)
    assert event_is_client_error({"ok": True}, _hint(exc)) is False


def test_keeps_runtime_error() -> None:
    event = {"ok": True}
    assert drop_client_error_event(event, _hint(RuntimeError("boom"))) is event


def test_detects_wrapped_client_error_cause() -> None:
    cause = _StubError(status_code=401)
    wrapped = RuntimeError("failed")
    wrapped.__cause__ = cause
    assert event_is_client_error({"ok": True}, _hint(wrapped)) is True


def test_detects_log_record_exc_info() -> None:
    exc = _StubError(status_code=400)
    record = SimpleNamespace(exc_info=(type(exc), exc, None))
    assert event_is_client_error({}, {"log_record": record}) is True


def test_drops_unauthorized_error_type_name() -> None:
    event = {"exception": {"values": [{"type": "UnauthorizedError", "value": "nope"}]}}
    assert event_is_client_error(event, None) is True


def test_drops_bad_request_error_type_name() -> None:
    event = {"exception": {"values": [{"type": "BadRequestError", "value": "nope"}]}}
    assert event_is_client_error(event, None) is True


def test_drops_no_token_message_log_event() -> None:
    event = {"logger": "usso", "message": "No token provided"}
    assert event_is_client_error(event, {}) is True
    assert drop_client_error_event(event, {}) is None


def test_drops_no_token_logentry_message() -> None:
    event = {"logentry": {"message": "No token provided", "params": []}}
    assert event_is_client_error(event, {}) is True


def test_drops_no_token_exception_value() -> None:
    event = {
        "exception": {"values": [{"type": "USSOError", "value": "No token provided"}]}
    }
    assert event_is_client_error(event, None) is True


def test_ignores_unrelated_message() -> None:
    event = {"message": "Something real broke"}
    assert event_is_client_error(event, {}) is False


def test_drops_http_422() -> None:
    exc = _StubError(status_code=422)
    event = {"ok": True}
    assert event_is_client_error(event, _hint(exc)) is True
    assert drop_client_error_event(event, _hint(exc)) is None


def test_drops_request_validation_error_type_name() -> None:
    event = {
        "exception": {"values": [{"type": "RequestValidationError", "value": "nope"}]}
    }
    assert event_is_client_error(event, None) is True


def test_drops_usso_error_type_name() -> None:
    event = {"exception": {"values": [{"type": "USSOError", "value": "nope"}]}}
    assert event_is_client_error(event, None) is True


def test_drops_usso_exception_type_name() -> None:
    event = {"exception": {"values": [{"type": "USSOException", "value": "nope"}]}}
    assert event_is_client_error(event, None) is True


def test_drops_validation_error_type_name() -> None:
    event = {"exception": {"values": [{"type": "ValidationError", "value": "nope"}]}}
    assert event_is_client_error(event, None) is True


def test_drops_request_validation_exception_message() -> None:
    event = {"message": "request_validation_exception occurred"}
    assert event_is_client_error(event, {}) is True


def test_drops_refresh_token_required_message() -> None:
    event = {"message": "Refresh token required"}
    assert event_is_client_error(event, {}) is True


def test_drops_usso_logger_unauthorized_message() -> None:
    event = {"logger": "usso", "message": "Unauthorized: invalid token"}
    assert event_is_client_error(event, {}) is True


def test_keeps_assertion_error() -> None:
    event = {"ok": True}
    assert drop_client_error_event(event, _hint(AssertionError("bad"))) is event
    assert event_is_client_error(event, _hint(AssertionError("bad"))) is False


def test_drop_processor_keeps_other_events() -> None:
    event = {"ok": True}
    assert drop_client_error_event(event, {}) is event


def test_status_code_reads_exception_attribute() -> None:
    from utils.sentry_filters import _status_code

    assert _status_code(None) is None
    assert _status_code(SimpleNamespace(status_code="401")) is None
    assert _status_code(SimpleNamespace(status_code=400)) == 400
    response = SimpleNamespace(status_code=401)
    assert _status_code(SimpleNamespace(response=response)) == 401


def test_exception_from_hint_ignores_empty_and_non_exc() -> None:
    from utils.sentry_filters import _exception_from_hint

    assert _exception_from_hint(None) is None
    assert _exception_from_hint({"exc_info": ("x",)}) is None
    assert _exception_from_hint({"log_record": SimpleNamespace(exc_info=None)}) is None


def test_detects_non_dict_exception_values_and_skips() -> None:
    event = {"exception": {"values": ["skip-me", {"type": "ValueError", "value": "x"}]}}
    assert event_is_client_error(event, None) is False


def test_install_is_noop_without_active_sentry(monkeypatch: object) -> None:
    import utils.sentry_filters as sentry_filters

    class _Inactive:
        def is_active(self) -> bool:
            return False

    sentry_filters._INSTALLED = False
    monkeypatch.setattr("sentry_sdk.get_client", lambda: _Inactive())
    assert install_client_error_filter() is False


def test_install_returns_true_when_already_installed() -> None:
    import utils.sentry_filters as sentry_filters

    sentry_filters._INSTALLED = True
    try:
        assert install_client_error_filter() is True
    finally:
        sentry_filters._INSTALLED = False


def test_install_returns_false_when_sentry_missing(monkeypatch: object) -> None:
    import builtins

    import utils.sentry_filters as sentry_filters

    sentry_filters._INSTALLED = False
    real_import = builtins.__import__

    def _fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "sentry_sdk":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    try:
        assert install_client_error_filter() is False
    finally:
        sentry_filters._INSTALLED = False


def test_install_attaches_processor_when_sentry_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import utils.sentry_filters as sentry_filters

    class _Active:
        def is_active(self) -> bool:
            return True

    added: list[object] = []

    class _Scope:
        def add_event_processor(self, processor: object) -> None:
            added.append(processor)

    sentry_filters._INSTALLED = False
    monkeypatch.setattr("sentry_sdk.get_client", lambda: _Active())
    monkeypatch.setattr("sentry_sdk.get_global_scope", lambda: _Scope())
    try:
        assert install_client_error_filter() is True
        assert added == [
            sentry_filters.scrub_sensitive_request_data,
            sentry_filters.drop_client_error_event,
            sentry_filters.drop_lifespan_shutdown_event,
        ]
    finally:
        sentry_filters._INSTALLED = False


def test_keeps_real_collection_was_not_initialized() -> None:
    from beanie.exceptions import CollectionWasNotInitialized

    exc = CollectionWasNotInitialized()
    event = {"ok": True}
    assert event_is_client_error(event, _hint(exc)) is False
    assert drop_client_error_event(event, _hint(exc)) is event


_LIFESPAN_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/usr/local/lib/python3.13/site-packages/starlette/routing.py", '
    "line 655, in lifespan\n"
    "    await receive()\n"
    "asyncio.exceptions.CancelledError\n"
)


def test_drops_lifespan_cancelled_error_logged_on_shutdown() -> None:
    event = {"message": _LIFESPAN_TRACEBACK}
    assert event_is_lifespan_shutdown_cancel(event, {}) is True
    assert drop_lifespan_shutdown_event(event, {}) is None


def test_drops_lifespan_cancel_from_logentry_and_exception_frames() -> None:
    logentry_event = {"logentry": {"formatted": _LIFESPAN_TRACEBACK}}
    assert event_is_lifespan_shutdown_cancel(logentry_event, {}) is True
    frames_event = {
        "exception": {
            "values": [
                {
                    "type": "CancelledError",
                    "value": "",
                    "stacktrace": {"frames": [{"function": "lifespan"}]},
                }
            ]
        }
    }
    assert event_is_lifespan_shutdown_cancel(frames_event, {}) is True


def test_keeps_cancelled_error_outside_lifespan() -> None:
    """A request cancelled mid-flight is not shutdown noise."""
    exc = asyncio.CancelledError()
    event = {"message": "Traceback ...\n  in handle_request\nCancelledError"}
    hint = {"exc_info": (type(exc), exc, None)}
    assert event_is_lifespan_shutdown_cancel(event, hint) is False
    assert drop_lifespan_shutdown_event(event, hint) is event


def test_keeps_real_errors_that_mention_lifespan() -> None:
    event = {"message": "RuntimeError: lifespan startup failed: no database"}
    assert event_is_lifespan_shutdown_cancel(event, {}) is False
    assert drop_lifespan_shutdown_event(event, {}) is event
