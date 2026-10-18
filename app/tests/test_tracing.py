"""
Regression tests for the shared trace-ID adapter (vendored ``tracing.py``).

Repo-local copy; keep the contract aligned with the other services.
Covers: ingress/echo, inbound validation (log injection), outbound httpx,
WebSocket handshake/tasks/errors, and the acceptance flow
ingress -> internal HTTP call -> async task -> provider webhook -> final call.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

try:
    from utils import tracing as t
except ImportError:
    try:  # services whose package is ``app`` (crypto-ipg, IPG gateways)
        from app import tracing as t
    except ImportError:  # mirza-connector
        from connector import tracing as t

HEADER = "X-Trace-ID"
VALID = "0192f3a4-5b6c-7d8e-9f01-23456789abcd"
EVIL = "abc\r\nX-Injected: 1\nforged log line"
SECRET = "Bearer sk-secret-token-123"
CONTENT = "private user message text"
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

seen_calls: list[httpx.Request] = []


def _downstream(request: httpx.Request) -> httpx.Response:
    seen_calls.append(request)
    return httpx.Response(200, json={"ok": True})


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(_downstream))


def _make_app(routes: list) -> Starlette:
    app = Starlette(routes=routes)
    t.install_tracing(app)
    return app


@pytest.fixture(autouse=True)
def _clear() -> None:
    seen_calls.clear()


# ------------------------------------------------------------ id generation


def test_new_trace_id_is_uuid7_and_time_ordered() -> None:
    first, second = t.new_trace_id(), t.new_trace_id()
    assert UUID_RE.match(first)
    assert uuid.UUID(first).version == 7
    assert first[:8] <= second[:8]


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        " ",
        "short",
        EVIL,
        "x" * 5000,
        f"{VALID}x",
        "0192f3a4-5b6c-7d8e-9f01-23456789abcg",
        b"\xff\xfe",
    ],
)
def test_malformed_input_is_replaced(raw: object) -> None:
    assert t.sanitize_trace_id(raw) is None
    assert UUID_RE.match(t.resolve_trace_id(raw))


def test_valid_input_is_kept_and_lowercased() -> None:
    assert t.resolve_trace_id(VALID.upper()) == VALID
    assert t.resolve_trace_id(f"  {VALID} ") == VALID
    assert t.resolve_trace_id(VALID.encode()) == VALID


# --------------------------------------------------------- HTTP ingress/echo


def _http_app() -> Starlette:
    async def whoami(request: Request) -> JSONResponse:  # ruff:ignore[unused-async]
        return JSONResponse({
            "ctx": t.get_trace_id(),
            "state": request.state.trace_id,
            "header": request.headers.get(HEADER),
        })

    async def boom(request: Request) -> JSONResponse:  # ruff:ignore[unused-async]
        raise RuntimeError(CONTENT)

    return _make_app([Route("/whoami", whoami), Route("/boom", boom)])


def test_missing_header_mints_uuid7_and_echoes() -> None:
    response = TestClient(_http_app()).get("/whoami")
    body = response.json()
    assert UUID_RE.match(response.headers[HEADER])
    assert body["ctx"] == body["state"] == body["header"] == response.headers[HEADER]


def test_valid_inbound_id_is_propagated_and_echoed() -> None:
    response = TestClient(_http_app()).get("/whoami", headers={HEADER: VALID.upper()})
    assert response.headers[HEADER] == VALID
    assert response.json() == {"ctx": VALID, "state": VALID, "header": VALID}


def test_malformed_inbound_id_is_replaced_and_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    response = TestClient(_http_app()).get("/whoami", headers={HEADER: "a" * 200})
    assert UUID_RE.match(response.headers[HEADER])
    assert "a" * 20 not in caplog.text
    assert "replaced" in caplog.text


def test_unhandled_error_response_still_carries_id() -> None:
    client = TestClient(_http_app(), raise_server_exceptions=False)
    response = client.get("/boom", headers={HEADER: VALID})
    assert response.status_code == 500
    assert response.headers[HEADER] == VALID
    assert CONTENT not in response.text


def test_context_is_reset_after_request() -> None:
    TestClient(_http_app()).get("/whoami")
    assert t.get_trace_id() is None


def test_outbound_internal_call_carries_inbound_id() -> None:
    async def call(request: Request) -> JSONResponse:
        async with _client() as client:
            await client.get(
                "http://ai-toolkit:8000/api/ai/v1/ocrs",
                headers={"Authorization": SECRET},
            )
        return JSONResponse({})

    app = _make_app([Route("/call", call)])
    TestClient(app).get("/call", headers={HEADER: VALID})
    sent = seen_calls[0]
    assert sent.headers[HEADER] == VALID
    assert sent.headers["Authorization"] == SECRET  # service auth untouched


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://saas:8000/x", True),
        ("http://localhost:8000/x", True),
        ("http://10.1.2.3/x", True),
        ("https://getmirza.ir/api/x", True),
        ("https://api.getmirza.ir/x", True),
        ("https://wallets.uln.me/api/accounting/v1/wallets", True),
        ("https://evil-uln.me/x", False),
        ("https://api.soniox.com/x", False),
        ("https://openrouter.ai/x", False),
        ("https://8.8.8.8/x", False),
        ("https://evilgetmirza.ir/x", False),
    ],
)
def test_only_internal_hosts_receive_the_id(
    url: str, expected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRACE_PROPAGATE_HOSTS", "getmirza.ir,uln.me")

    async def run() -> None:
        with t.trace_scope(VALID):
            async with _client() as client:
                await client.get(url)

    asyncio.run(run())
    assert (HEADER in seen_calls[0].headers) is expected


def test_explicit_header_wins_and_no_context_means_no_header() -> None:
    async def run() -> None:
        async with _client() as client:
            await client.get("http://saas:8000/a")
            with t.trace_scope(VALID):
                await client.get("http://saas:8000/b", headers={HEADER: "explicit"})

    asyncio.run(run())
    assert HEADER not in seen_calls[0].headers
    assert seen_calls[1].headers[HEADER] == "explicit"


def test_sync_client_and_bare_client_are_covered() -> None:
    with (
        t.trace_scope(VALID),
        httpx.Client(transport=httpx.MockTransport(_downstream)) as client,
    ):
        client.post("http://shop:8000/x", json={})
    assert seen_calls[0].headers[HEADER] == VALID


def test_extra_hosts_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRACE_PROPAGATE_HOSTS", "partner.example.org")
    assert t.is_internal_host("api.partner.example.org")
    assert not t.is_internal_host("api.example.org")


def test_install_is_idempotent() -> None:
    before = httpx.AsyncClient.send
    t.install_httpx_propagation()
    assert httpx.AsyncClient.send is before


# ---------------------------------------------------------------- WebSocket


def _ws_app(child_ids: list) -> Starlette:
    async def echo(websocket: WebSocket) -> None:
        await websocket.accept()
        child_ids.append(("handler", t.get_trace_id()))

        async def child() -> None:
            child_ids.append(("task", t.get_trace_id()))
            async with _client() as client:
                await client.get("http://ai-toolkit:8000/api/ai/v1/transcribes")

        await asyncio.create_task(child())
        await websocket.send_json({"trace": t.get_trace_id()})
        await websocket.close()

    async def reject(websocket: WebSocket) -> None:
        await websocket.close(code=4401)

    async def fail(websocket: WebSocket) -> None:
        await websocket.accept()
        raise RuntimeError(CONTENT)

    return _make_app([
        WebSocketRoute("/ws", echo),
        WebSocketRoute("/deny", reject),
        WebSocketRoute("/err", fail),
    ])


def _echoed(headers: object) -> str | None:
    for key, value in headers or ():
        if bytes(key).lower() == b"x-trace-id":
            return bytes(value).decode()
    return None


def test_websocket_accept_echoes_id_and_tasks_inherit_it() -> None:
    ids: list = []
    with TestClient(_ws_app(ids)).websocket_connect(
        "/ws", headers={HEADER: VALID}
    ) as ws:
        assert _echoed(ws.extra_headers) == VALID
        assert ws.receive_json() == {"trace": VALID}
    assert ids == [("handler", VALID), ("task", VALID)]
    assert seen_calls[0].headers[HEADER] == VALID


def test_websocket_without_header_mints_id() -> None:
    with TestClient(_ws_app([])).websocket_connect("/ws") as ws:
        minted = _echoed(ws.extra_headers)
        assert UUID_RE.match(minted)
        assert ws.receive_json() == {"trace": minted}


def test_websocket_malformed_header_is_replaced() -> None:
    with TestClient(_ws_app([])).websocket_connect(
        "/ws", headers={HEADER: "bad value"}
    ) as ws:
        assert UUID_RE.match(_echoed(ws.extra_headers))


def test_websocket_handshake_rejection_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    with (
        pytest.raises(WebSocketDisconnect),
        TestClient(_ws_app([])).websocket_connect("/deny", headers={HEADER: VALID}),
    ):
        pass
    record = next(r for r in caplog.records if "handshake rejected" in r.getMessage())
    assert "4401" in record.getMessage()


def test_websocket_error_is_logged_without_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    with (
        pytest.raises(RuntimeError),
        TestClient(_ws_app([])).websocket_connect("/err") as ws,
    ):
        ws.receive_text()
    assert "websocket failed: RuntimeError" in caplog.text
    assert CONTENT not in caplog.text


# ---------------------------------------------------- task / webhook continuity


def test_meta_stamp_scope_and_adopt() -> None:
    assert "trace_id" not in t.stamp_meta({"a": 1})
    with t.trace_scope(VALID):
        assert t.stamp_meta({"a": 1}) == {"a": 1, "trace_id": VALID}
        other = "0192f3a4-5b6c-7d8e-9f01-23456789aaaa"
        assert t.stamp_meta({"trace_id": other})["trace_id"] == other  # caller wins
        assert t.stamp_meta({"trace_id": EVIL})["trace_id"] == VALID  # invalid replaced
    with t.trace_scope(None) as minted:  # nothing stored, nothing active
        assert UUID_RE.match(minted)
    with t.trace_scope(VALID), t.trace_scope("not-an-id") as kept:
        assert kept == VALID
    assert t.get_trace_id() is None


def test_adopt_rejects_unusable_ids() -> None:
    with t.trace_scope(VALID):
        assert t.adopt_trace_id(EVIL) is None
        assert t.get_trace_id() == VALID


def test_acceptance_ingress_to_downstream_task_and_webhook(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Carry one ID through ingress, tasks, provider webhook and final call."""
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger("acceptance")
    tasks: dict[str, dict] = {}
    background_tasks: set[asyncio.Task] = set()

    async def submit(request: Request) -> JSONResponse:
        body = await request.json()
        meta = t.stamp_meta(body.get("meta_data"))
        tasks["job"] = {"meta_data": meta, "text": body["text"]}
        async with _client() as client:  # e.g. finance / metering call
            await client.post(
                "http://saas:8000/api/saas/v1/usage",
                json={"amount": 1},
                headers={"x-api-key": SECRET},
            )
        task = asyncio.create_task(_run(tasks["job"]))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)
        return JSONResponse({"uid": "job"}, status_code=201)

    async def _run(job: dict) -> None:
        with t.trace_scope(job["meta_data"].get("trace_id")):
            logger.info("job running")
            async with _client() as client:  # e.g. media / provider submit
                await client.post("http://media:8000/api/media/v1/files", json={})

    async def provider_webhook(request: Request) -> JSONResponse:
        ingress = t.get_trace_id()  # provider cannot send our header
        job = tasks["job"]
        t.adopt_trace_id(job["meta_data"].get("trace_id"))
        logger.info("webhook handled")
        async with _client() as client:  # final delivery to the bot
            await client.post(
                "http://mirza-bot:8000/api/bot/v1/transcribe/webhook/",
                json={"meta_data": job["meta_data"]},
            )
        return JSONResponse({"ingress": ingress})

    app = _make_app([
        Route("/submit", submit, methods=["POST"]),
        Route("/hook", provider_webhook, methods=["POST"]),
    ])
    client = TestClient(app)
    submitted = client.post("/submit", json={"text": CONTENT}, headers={HEADER: VALID})
    assert submitted.headers[HEADER] == VALID

    import time

    deadline = time.time() + 2
    while len(seen_calls) < 2 and time.time() < deadline:
        time.sleep(0.01)  # task runs on the TestClient portal loop

    hook = client.post("/hook")  # separate request, new ingress ID
    assert hook.json()["ingress"] != VALID

    sent = {str(r.url.host): r.headers.get(HEADER) for r in seen_calls}
    assert sent == {"saas": VALID, "media": VALID, "mirza-bot": VALID}
    assert tasks["job"]["meta_data"]["trace_id"] == VALID
    assert "adopted" in caplog.text
    assert {r.trace_id for r in caplog.records if r.name == "acceptance"} == {VALID}
    assert CONTENT not in caplog.text
    assert SECRET not in caplog.text


def test_log_records_carry_trace_id() -> None:
    t.install_log_record_trace_id()
    record = logging.getLogger("x").makeRecord("x", logging.INFO, "f", 1, "m", (), None)
    assert record.trace_id == "-"
    with t.trace_scope(VALID):
        record = logging.getLogger("x").makeRecord(
            "x", logging.INFO, "f", 1, "m", (), None
        )
    assert record.trace_id == VALID


def test_install_survives_replaced_httpx_client_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests often swap ``httpx.AsyncClient`` for a factory; install must not break."""
    t.install_httpx_propagation()
    patched_async, patched_sync = t._AsyncClient.send, t._Client.send
    monkeypatch.setattr(t._AsyncClient, "send", patched_async.__wrapped__)
    monkeypatch.setattr(t._Client, "send", patched_sync.__wrapped__)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: None)
    t.install_httpx_propagation()
    assert getattr(t._AsyncClient.send, t._SENTINEL, False)
    assert getattr(t._Client.send, t._SENTINEL, False)
