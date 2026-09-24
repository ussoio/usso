"""SMTP email channel."""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from pydantic import BaseModel, Field

from .base import AbstractChannel


class SMTPConfig(BaseModel):
    """SMTP config."""

    host: str = Field(..., description="SMTP server host")
    port: int = Field(..., description="SMTP server port")
    username: str = Field(..., description="SMTP username")
    password: str = Field(..., description="SMTP password")
    sender: str = Field(..., description="Email address of the sender")
    use_tls: bool = Field(default=False, description="Whether to use TLS")
    use_ssl: bool = Field(default=True, description="Whether to use SSL")
    verify_ssl: bool = Field(default=True, description="Whether to verify SSL")
    timeout: int = Field(default=30, description="SMTP connection timeout")


def send_email(
    *,
    smtp_config: SMTPConfig | dict,
    to_email: str,
    text: str,
    subject: str | None = None,
    **kwargs: object,
) -> None:
    """
    Send an email.

    Args:
        smtp_config: The SMTP configuration
        to_email: The email address
        text: The message
        subject: The subject
        **kwargs: Additional arguments

    Returns:
        None.

    """
    # Create email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_config.sender
    msg["To"] = to_email
    msg.attach(MIMEText(text, "html"))

    # Send email with SMTP
    if smtp_config.use_ssl:
        server = smtplib.SMTP_SSL(
            smtp_config.host, smtp_config.port, timeout=smtp_config.timeout
        )
    else:
        server = smtplib.SMTP(
            smtp_config.host, smtp_config.port, timeout=smtp_config.timeout
        )
        if smtp_config.use_tls:
            server.starttls()
    if smtp_config.username and smtp_config.password:
        server.login(smtp_config.username, smtp_config.password)
    server.sendmail(smtp_config.sender, [to_email], msg.as_string())
    server.quit()


class SMTPEmailChannel(AbstractChannel):
    """SMTP email channel."""

    channel_type = "email"
    supports_phone = False
    ConfigType = SMTPConfig

    def send(self, *, to: str, message: str, subject: str, **kwargs: object) -> None:
        """
        Send an email.

        Args:
            to: The email address
            message: The message
            subject: The subject
            **kwargs: Additional arguments

        Returns:
            None.

        """
        send_email(
            smtp_config=self.config,
            to_email=to,
            text=message,
            subject=subject,
        )
