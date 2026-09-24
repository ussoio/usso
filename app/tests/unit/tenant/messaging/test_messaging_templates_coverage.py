"""Focused branch coverage for messaging templates."""

from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest
from pydantic import ValidationError

from apps.tenant.messaging import templates
from apps.tenant.messaging.enums import (
    MessageChannelType,
    TemplateSourceType,
    TemplateType,
)
from apps.tenant.messaging.templates import DEFAULT_TEMPLATE_SET, MessageTemplate


def test_template_path_and_remote_size_boundaries() -> None:
    with pytest.raises(ValueError, match="required"):
        templates._safe_template_path(None)
    with pytest.raises(ValueError, match="bundled template"):
        templates._safe_template_path("/etc/passwd")

    by_header = MagicMock(
        headers={"content-length": str(templates._MAX_REMOTE_TEMPLATE_BYTES + 1)},
        content=b"",
    )
    with pytest.raises(ValueError, match="too large"):
        templates._bounded_response_text(by_header)

    by_body = MagicMock(
        headers={},
        content=b"x" * (templates._MAX_REMOTE_TEMPLATE_BYTES + 1),
    )
    with pytest.raises(ValueError, match="too large"):
        templates._bounded_response_text(by_body)


def test_enum_validators_accept_strings_and_enum_instances() -> None:
    template = MessageTemplate(
        template_type="magic_link", channel="sms", source_type="inline"
    )
    assert template.template_type is TemplateType.magic_link
    assert template.channel is MessageChannelType.SMS
    assert template.source_type is TemplateSourceType.INLINE

    existing = MessageTemplate(
        template_type=TemplateType.sms_otp,
        channel=MessageChannelType.BALE,
        source_type=TemplateSourceType.REMOTE,
    )
    assert existing.template_type is TemplateType.sms_otp
    assert existing.channel is MessageChannelType.BALE
    assert existing.source_type is TemplateSourceType.REMOTE


@pytest.mark.parametrize(
    ("field", "value"),
    [("template_type", "unknown"), ("channel", "fax"), ("source_type", "db")],
)
def test_enum_validators_reject_unknown_values(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        MessageTemplate(**{field: value})


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (TemplateSourceType.FILE, True),
        (TemplateSourceType.URL, True),
        (TemplateSourceType.INLINE, True),
        (TemplateSourceType.REMOTE, False),
    ],
)
def test_is_renderable_locally(source: TemplateSourceType, expected: bool) -> None:
    assert MessageTemplate(source_type=source).is_renderable_locally() is expected


def test_get_raw_template_file() -> None:
    template = MessageTemplate(source_type="file", path="message.jinja2")
    opened = mock_open(read_data="Hello {{ name }}")
    safe_path = MagicMock()
    safe_path.open = opened
    with patch(
        "apps.tenant.messaging.templates._safe_template_path",
        return_value=safe_path,
    ):
        assert template.get_raw_template() == "Hello {{ name }}"
    opened.assert_called_once_with(encoding="utf-8")


def test_get_raw_template_url() -> None:
    response = MagicMock(text="remote body", content=b"remote body", headers={})
    client = MagicMock()
    client.get.return_value = response
    client.__enter__.return_value = client
    with (
        patch("apps.tenant.messaging.templates.validate_public_url_sync") as validate,
        patch("apps.tenant.messaging.templates.httpx.Client", return_value=client),
    ):
        template = MessageTemplate(source_type="url", url="https://templates.test/a")
        assert template.get_raw_template() == "remote body"
    validate.assert_called_once_with("https://templates.test/a")
    client.get.assert_called_once_with("https://templates.test/a")
    response.raise_for_status.assert_called_once_with()


def test_get_raw_template_inline_and_remote() -> None:
    assert (
        MessageTemplate(source_type="inline", inline_body="body").get_raw_template()
        == "body"
    )
    with pytest.raises(TypeError, match="third-party"):
        MessageTemplate(source_type="remote").get_raw_template()


def test_validate_context_and_render_with_autoescape() -> None:
    template = MessageTemplate(
        name="welcome",
        source_type="inline",
        inline_body="Hello {{ name }}",
        variables=["name"],
    )
    with pytest.raises(ValueError, match=r"\['name'\]"):
        template.validate_context({})
    assert template.render({"name": "<Mahdi>"}) == "Hello &lt;Mahdi&gt;"


def test_render_remote_returns_none_without_context_validation() -> None:
    template = MessageTemplate(source_type="remote", variables=["required"])
    assert template.render({}) is None


@pytest.mark.asyncio
async def test_aget_raw_template_url() -> None:
    response = MagicMock(text="async body", content=b"async body", headers={})
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    with (
        patch(
            "apps.tenant.messaging.templates.validate_public_url",
            new=AsyncMock(),
        ) as validate,
        patch("apps.tenant.messaging.templates.httpx.AsyncClient", return_value=client),
    ):
        template = MessageTemplate(source_type="url", url="https://templates.test/a")
        assert await template.aget_raw_template() == "async body"
    validate.assert_awaited_once_with("https://templates.test/a")
    client.get.assert_awaited_once_with("https://templates.test/a", timeout=10)
    response.raise_for_status.assert_called_once_with()


@pytest.mark.asyncio
async def test_aget_raw_template_delegates_and_arender_branches() -> None:
    template = MessageTemplate(
        name="async",
        source_type="inline",
        inline_body="{{ value }}",
        variables=["value"],
    )
    with patch.object(
        MessageTemplate, "get_raw_template", return_value="raw"
    ) as get_raw:
        assert await template.aget_raw_template() == "raw"
    get_raw.assert_called_once_with()

    assert await template.arender({"value": "<ok>"}) == "&lt;ok&gt;"
    assert await MessageTemplate(source_type="remote").arender({}) is None


def test_default_template_set_contains_builtin_templates() -> None:
    from apps.tenant.messaging.enums import TemplateType

    assert {
        TemplateType.verification,
        TemplateType.reset_password,
        TemplateType.magic_link,
        TemplateType.email_otp,
        TemplateType.sms_otp,
    } <= set(DEFAULT_TEMPLATE_SET)
