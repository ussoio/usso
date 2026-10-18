"""Tests for the env-configured bootstrap public OAuth client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apps.tenant import startup


def test_public_client_from_env_disabled_without_client_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BOOTSTRAP_PUBLIC_CLIENT_ID", raising=False)
    assert startup._public_client_from_env() is None

    monkeypatch.setenv("BOOTSTRAP_PUBLIC_CLIENT_ID", "   ")
    assert startup._public_client_from_env() is None


def test_public_client_from_env_parses_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BOOTSTRAP_PUBLIC_CLIENT_ID", "ext")
    monkeypatch.setenv("BOOTSTRAP_PUBLIC_CLIENT_NAME", "Extension")
    monkeypatch.setenv(
        "BOOTSTRAP_PUBLIC_CLIENT_REDIRECT_URIS",
        " https://a.example/ ,,https://b.example/",
    )

    assert startup._public_client_from_env() == {
        "client_id": "ext",
        "client_name": "Extension",
        "redirect_uris": ["https://a.example/", "https://b.example/"],
    }


def test_public_client_name_defaults_to_client_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BOOTSTRAP_PUBLIC_CLIENT_ID", "ext")
    monkeypatch.delenv("BOOTSTRAP_PUBLIC_CLIENT_NAME", raising=False)
    monkeypatch.delenv("BOOTSTRAP_PUBLIC_CLIENT_REDIRECT_URIS", raising=False)

    spec = startup._public_client_from_env()
    assert spec == {"client_id": "ext", "client_name": "ext", "redirect_uris": []}


@pytest.mark.asyncio
async def test_ensure_bootstrap_public_client_noop_without_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BOOTSTRAP_PUBLIC_CLIENT_ID", raising=False)
    with patch.object(startup.Tenant, "find") as find:
        await startup.ensure_bootstrap_public_client()
    find.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_bootstrap_public_client_creates_only_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BOOTSTRAP_PUBLIC_CLIENT_ID", "ext")
    monkeypatch.setenv("BOOTSTRAP_PUBLIC_CLIENT_REDIRECT_URIS", "https://a.example/")

    with_client = MagicMock(uid="t1", user_id="u1")
    without_client = MagicMock(uid="t2", user_id="u2")
    cursor = MagicMock()
    cursor.to_list = AsyncMock(return_value=[with_client, without_client])

    def find_one(query: dict) -> object | None:
        return object() if query["tenant_id"] == "t1" else None

    created = MagicMock()
    created.save = AsyncMock()
    with (
        patch.object(startup.Tenant, "find", return_value=cursor),
        patch.object(startup, "OAuthClient", wraps=startup.OAuthClient) as client_cls,
    ):
        client_cls.find_one = AsyncMock(side_effect=find_one)
        client_cls.return_value = created
        await startup.ensure_bootstrap_public_client()

    client_cls.assert_called_once()
    kwargs = client_cls.call_args.kwargs
    assert kwargs["tenant_id"] == "t2"
    assert kwargs["client_id"] == "ext"
    assert kwargs["redirect_uris"] == ["https://a.example/"]
    assert kwargs["client_secret"] is None
    created.save.assert_awaited_once()
