"""
Magic link service module.

This module handles magic link generation, validation, and sending.
"""

import asyncio
import logging
import secrets
import time
import uuid
from collections.abc import Coroutine
from datetime import datetime, timedelta

from fastapi_mongo_base.utils import timezone

from server.config import Settings
from server.exceptions import TooManyRequestsError
from utils.hasher import PasswordHasherService

from ....tenant.messaging import services as messaging_services
from ....tenant.messaging.enums import MessageChannelType
from ....tenant.models import Tenant
from ...user.models import Credential, User
from ...user.services import (
    find_or_create_user,
)
from ..enums import AuthIdentifier, AuthSecret, AuthStep
from ..schemas import (
    MagicLinkRequest,
    OTPRequest,
)
from .basics import sanitize_origin

logger = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task[object]] = set()


def _schedule_background_task(coro: Coroutine[object, object, object]) -> None:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)

    def _done(done: asyncio.Task[object]) -> None:
        _background_tasks.discard(done)
        if done.cancelled():
            return
        exc = done.exception()
        if exc is not None:
            logger.exception(
                "Background messaging task failed: %s",
                type(exc).__name__,
                exc_info=exc,
            )

    task.add_done_callback(_done)


async def send_magic_link(
    *, tenant: Tenant, origin: str, data: MagicLinkRequest
) -> None:
    """Send magic link email."""
    user, is_created = await find_or_create_user(login_request=data, tenant=tenant)
    if is_created:
        user_identifier = data
    else:
        for user_identifier in await user.get_identifiers():
            if user_identifier.type == AuthIdentifier.EMAIL:
                break
        else:
            user_identifier = data

    # Generate magic link token
    # Never derive an authentication link from the client-controlled Origin header.
    tenant_url = tenant.primary_url
    logger.info("Sending magic link for tenant %s", tenant.uid)
    now = int(time.time())
    expiry_seconds = tenant.config.auth.magic_link_timeout

    # Build payload with identifier
    payload = {
        "iss": tenant_url,
        "aud": tenant_url,
        "iat": now,
        "exp": now + expiry_seconds,
        "jti": str(uuid.uuid4()),
        "sub": user_identifier.identifier,
    }

    # Add identifier-specific field for determine_identifier_type
    if user_identifier.type == AuthIdentifier.EMAIL:
        payload["email"] = user_identifier.identifier
    elif user_identifier.type == AuthIdentifier.PHONE:
        payload["phone"] = user_identifier.identifier
    elif user_identifier.type == AuthIdentifier.USERNAME:
        payload["username"] = user_identifier.identifier
    elif user_identifier.type == AuthIdentifier.NATIONAL_ID:
        payload["national_id"] = user_identifier.identifier

    # Sign the token
    token = tenant.sign_jwt(payload, hmac=False)

    # Build magic link URL
    magic_link_url = f"{tenant_url}{Settings.base_path}/auth/magic-link?token={token}"

    template_type = "magic_link"
    context = {
        "tenant": tenant,
        "user": user,
        "expiry_minutes": int(expiry_seconds / 60),
        "magic_link": magic_link_url,
    }
    await messaging_services.asend(
        tenant=tenant,
        channel=MessageChannelType.EMAIL,
        to=user_identifier.identifier,
        template_type=template_type,
        context=context,
    )


def _generate_random_otp(length: int) -> int:
    """
    Generate an OTP with a CSPRNG in every environment.

    Never mock this with a fixed value: a DEBUG flag left on in production
    turned every OTP into 123456 (account takeover).
    """
    return secrets.randbelow(10**length)


async def create_otp(
    *, otp_request: OTPRequest, tenant: Tenant, origin: str | None = None
) -> int:
    """Create and send OTP."""
    from apps.tenant.messaging.channels.base import AbstractChannel

    resolved_type = AbstractChannel.resolve_channel_type(
        typ=otp_request.channel_type, tenant=tenant
    )
    otp_request.channel_type = resolved_type
    channel: AbstractChannel = otp_request.get_channel(tenant)
    user, is_created = await find_or_create_user(
        login_request=otp_request, tenant=tenant
    )

    if is_created:
        user_identifier = otp_request
    else:
        for user_identifier in await user.get_identifiers():
            if user_identifier.type == MessageChannelType.get_identifier_type(
                otp_request.channel_type
            ):
                break
        else:
            user_identifier = otp_request

    is_phone = channel.channel_type in AbstractChannel.tenant_phone_channel_types(
        tenant
    )
    template_type = "sms_otp" if is_phone else "email_otp"
    otp = _generate_random_otp(tenant.config.auth.otp_length)
    otp_code = f"{otp:0{tenant.config.auth.otp_length}d}"
    context = {
        "otp_code": otp_code,
        "tenant": tenant,
        "user": user,
        "expiry_minutes": int(tenant.config.auth.otp_timeout / 60),
        "origin": origin or tenant.primary_domain,
    }

    # only two active OTP is allowed
    query = Credential.get_query(
        tenant_id=tenant.uid,
        user_id=user.uid,
        method=(AuthSecret.PHONE_OTP if is_phone else AuthSecret.EMAIL_OTP),
        is_active=True,
    )
    if await query.count() > 3:
        raise TooManyRequestsError(
            error_code="too_many_requests",
            detail="Too many OTP requests",
            message={
                "en": "Too many OTP requests",
                "fa": "درخواست‌های زیادی ارسال کرده‌اید. لطفاً کمی صبر کنید.",
            },
        )

    latest: Credential | None = await query.sort("-created_at").first_or_none()
    latest_created_at: datetime = latest.created_at if latest else datetime.now()
    await query.find({"created_at": {"$lt": latest_created_at}}).update_many({
        "$set": {"is_active": False}
    })

    credential = Credential(
        tenant_id=tenant.uid,
        user_id=user.uid,
        secret=PasswordHasherService().hash_password(otp_code),
        meta_data={"identifier": otp_request.identifier},
        method=(AuthSecret.PHONE_OTP if is_phone else AuthSecret.EMAIL_OTP),
        expires_at=(
            datetime.now(timezone.tz)
            + timedelta(seconds=tenant.config.auth.otp_timeout)
        ),
    )
    await credential.save()

    logger.info("Sending one-time code via %s", channel.channel_type)
    _schedule_background_task(
        messaging_services.asend(
            tenant=tenant,
            channel=channel.channel_type,
            to=user_identifier.identifier,
            template_type=template_type,
            context=context,
        ),
    )
    return otp


async def check_otp_needed_and_send(
    next_step: AuthStep,
    user: User,
    tenant: Tenant,
    origin: str | None = None,
    amr: list[str] | None = None,
) -> None:
    """Check if OTP is needed and send it."""
    amr = amr or []
    identifiers = await user.get_identifiers()
    active_credentials = await user.get_credentials()
    origin = sanitize_origin(origin)

    if (
        AuthSecret.PHONE_OTP in next_step.methods
        and AuthSecret.PHONE_OTP not in amr
        and not any(c.method == AuthSecret.PHONE_OTP for c in active_credentials)
    ):
        phones = [i.identifier for i in identifiers if i.type == AuthIdentifier.PHONE]
        for phone in phones:
            await create_otp(
                otp_request=OTPRequest(
                    type=AuthIdentifier.PHONE,
                    identifier=phone,
                ),
                tenant=tenant,
                origin=origin,
            )

    if (
        AuthSecret.EMAIL_OTP in next_step.methods
        and AuthSecret.EMAIL_OTP not in amr
        and not any(c.method == AuthSecret.EMAIL_OTP for c in active_credentials)
    ):
        emails = [i.identifier for i in identifiers if i.type == AuthIdentifier.EMAIL]
        for email in emails:
            await create_otp(
                otp_request=OTPRequest(
                    type=AuthIdentifier.EMAIL,
                    identifier=email,
                ),
                tenant=tenant,
            )
