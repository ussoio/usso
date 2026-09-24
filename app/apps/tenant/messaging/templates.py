"""Messaging templates."""

from pathlib import Path

import httpx
from jinja2 import DictLoader, StrictUndefined
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, Field, field_validator

from utils.outbound import validate_public_url, validate_public_url_sync

from .enums import MessageChannelType, TemplateSourceType, TemplateType

_TEMPLATE_ROOT = (Path(__file__).parent / "templates").resolve()
_MAX_REMOTE_TEMPLATE_BYTES = 256 * 1024


def _safe_template_path(path: str | None) -> Path:
    """Resolve bundled templates without allowing arbitrary file reads."""
    if not path:
        raise ValueError("Template path is required")
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(_TEMPLATE_ROOT):
        raise ValueError("Template path must be inside the bundled template directory")
    return resolved


def _render_environment(raw: str, name: str) -> SandboxedEnvironment:
    """Build a sandboxed Jinja environment for tenant-controlled templates."""
    return SandboxedEnvironment(
        loader=DictLoader({name: raw}),
        autoescape=True,
        undefined=StrictUndefined,
    )


def _bounded_response_text(response: httpx.Response) -> str:
    content_length = int(response.headers.get("content-length") or 0)
    if content_length > _MAX_REMOTE_TEMPLATE_BYTES:
        raise ValueError("Remote template is too large")
    if len(response.content) > _MAX_REMOTE_TEMPLATE_BYTES:
        raise ValueError("Remote template is too large")
    return response.text


class MessageTemplate(BaseModel):
    """Message template."""

    name: str = Field(default="message_template", description="Name of the template")
    template_type: TemplateType = TemplateType.email_otp
    channel: MessageChannelType = MessageChannelType.EMAIL
    source_type: TemplateSourceType = TemplateSourceType.FILE
    subject: str | None = None

    path: str | None = None
    url: str | None = None
    inline_body: str | None = None
    remote_template_id: str | None = None

    variables: list[str] = Field(default_factory=list)

    @field_validator("template_type", mode="before")
    @classmethod
    def validate_template_type(cls, v: TemplateType | str) -> TemplateType:
        """Validate the template type."""
        if isinstance(v, TemplateType):
            return v
        return TemplateType(v)

    @field_validator("channel", mode="before")
    @classmethod
    def validate_channel(cls, v: MessageChannelType | str) -> MessageChannelType:
        """Validate the channel."""
        if isinstance(v, MessageChannelType):
            return v
        return MessageChannelType(v)

    @field_validator("source_type", mode="before")
    @classmethod
    def validate_source_type(cls, v: TemplateSourceType | str) -> TemplateSourceType:
        """Validate the source type."""
        if isinstance(v, TemplateSourceType):
            return v
        return TemplateSourceType(v)

    def is_renderable_locally(self) -> bool:
        """Check if the template is renderable locally."""
        return self.source_type in {
            TemplateSourceType.FILE,
            TemplateSourceType.URL,
            TemplateSourceType.INLINE,
        }

    def get_raw_template(self) -> str:
        """Get the raw template."""
        match self.source_type:
            case TemplateSourceType.FILE:
                with _safe_template_path(self.path).open(encoding="utf-8") as f:
                    return f.read()
            case TemplateSourceType.URL:
                validate_public_url_sync(self.url)
                with httpx.Client(
                    follow_redirects=False,
                    trust_env=False,
                    timeout=10,
                ) as client:
                    resp = client.get(self.url)
                resp.raise_for_status()
                return _bounded_response_text(resp)
            case TemplateSourceType.INLINE:
                return self.inline_body
            case TemplateSourceType.REMOTE:
                raise TypeError("Remote templates are handled by third-party service.")

    def validate_context(self, context: dict) -> None:
        """Validate the context."""
        missing = [key for key in self.variables if key not in context]
        if missing:
            raise ValueError(f"Missing required variables for template: {missing}")

    def render(self, context: dict) -> str | None:
        """
        Render the template with given context.

        Return string if renderable, otherwise None (for REMOTE templates).
        """
        if not self.is_renderable_locally():
            return None  # Remote templates aren't rendered here

        self.validate_context(context)
        raw = self.get_raw_template()

        env = _render_environment(raw, self.name)
        template = env.get_template(self.name)

        return template.render(**context)

    async def aget_raw_template(self) -> str:
        """Get the raw template."""
        if self.source_type == TemplateSourceType.URL:
            await validate_public_url(self.url)
            async with httpx.AsyncClient(
                follow_redirects=False,
                trust_env=False,
            ) as client:
                resp = await client.get(self.url, timeout=10)
                resp.raise_for_status()
                return _bounded_response_text(resp)

        return self.get_raw_template()

    async def arender(self, context: dict) -> str | None:
        """
        Render the template with given context.

        Return string if renderable, otherwise None (for REMOTE templates).
        """
        if not self.is_renderable_locally():
            return None  # Remote templates aren't rendered here

        self.validate_context(context)
        raw = await self.aget_raw_template()

        env = _render_environment(raw, self.name)
        template = env.get_template(self.name)

        return template.render(**context)


cur_dir = Path(__file__).parent if "__file__" in globals() else Path(".")
DEFAULT_TEMPLATE_SET = {
    TemplateType.verification: MessageTemplate(
        template_type=TemplateType.verification,
        channel=MessageChannelType.EMAIL,
        source_type=TemplateSourceType.FILE,
        subject="Verify Your Email Address",
        path=str(cur_dir / "templates" / "verification.jinja2"),
        variables=["user", "verification_url", "expiry_minutes", "tenant"],
    ),
    TemplateType.reset_password: MessageTemplate(
        subject="Reset Your Password",
        template_type=TemplateType.reset_password,
        source_type=TemplateSourceType.FILE,
        path=str(cur_dir / "templates" / "reset_password.jinja2"),
        variables=["user", "reset_password_url", "expiry_minutes", "tenant"],
    ),
    TemplateType.magic_link: MessageTemplate(
        subject="Your Login Link",
        template_type=TemplateType.magic_link,
        source_type=TemplateSourceType.FILE,
        path=str(cur_dir / "templates" / "magic_link.jinja2"),
        variables=["user", "magic_link_url", "expiry_minutes", "tenant"],
    ),
    TemplateType.email_otp: MessageTemplate(
        subject="Your Verification Code",
        template_type=TemplateType.email_otp,
        source_type=TemplateSourceType.FILE,
        path=str(cur_dir / "templates" / "email_otp.jinja2"),
        variables=["user", "otp_code", "expiry_minutes", "tenant"],
    ),
    TemplateType.sms_otp: MessageTemplate(
        subject="Your Verification Code",
        template_type=TemplateType.sms_otp,
        source_type=TemplateSourceType.FILE,
        path=str(cur_dir / "templates" / "sms_otp.jinja2"),
        variables=["otp_code", "tenant"],
    ),
}
