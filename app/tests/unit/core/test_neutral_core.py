"""The generic core must remain deployable without any product overlay."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from server import extensions
from utils import tracing


def test_extensions_are_opt_in() -> None:
    with patch.object(extensions, "import_module") as load:
        extensions.load_extensions(MagicMock(), " , ")
    load.assert_not_called()


def test_extensions_are_ordered_and_installed_once() -> None:
    app = MagicMock()
    first, second = MagicMock(), MagicMock()
    with patch.object(extensions, "import_module", side_effect=[first, second]) as load:
        extensions.load_extensions(app, " first , second,first ")
    assert [call.args[0] for call in load.call_args_list] == ["first", "second"]
    first.install.assert_called_once_with(app)
    second.install.assert_called_once_with(app)


def test_invalid_extension_fails_closed() -> None:
    with (
        patch.object(extensions, "import_module", return_value=SimpleNamespace()),
        pytest.raises(AttributeError),
    ):
        extensions.load_extensions(MagicMock(), "invalid")


def test_trace_domains_are_deployment_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TRACE_PROPAGATE_HOSTS", raising=False)
    assert not tracing.is_internal_host("api.deployment.example.test")
    monkeypatch.setenv("TRACE_PROPAGATE_HOSTS", "deployment.example.test")
    assert tracing.is_internal_host("api.deployment.example.test")
    assert not tracing.is_internal_host("deployment.example.test.attacker.test")


def test_core_has_no_product_provisioning_or_tracked_environment_backup() -> None:
    app = Path(__file__).parents[3]
    for folder in ("apps", "server", "utils"):
        for source in (app / folder).rglob("*.py"):
            text = source.read_text()
            assert "getmirza.ir" not in text, source
            assert "apps.ice" not in text, source
            assert "ensure_mirza_flow_client" not in text, source
    assert not list(app.parent.glob(".env.bak*"))
