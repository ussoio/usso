"""Credential services for user authentication."""

import base64
import io
from datetime import datetime, timedelta

import pyotp
import qrcode
import qrcode.constants
import webauthn
from fastapi_mongo_base.utils import timezone
from usso import UserData

from apps.tenant.models import Tenant
from server.db import redis
from server.exceptions import BadRequestError, NotFoundError, UnauthorizedError
from utils import texttools

from ..profile.models import Profile
from . import models, schemas, services


def get_rp_id(hostname: str | None = None, tenant_domain: str | None = None) -> str:
    """Get relying party ID from hostname or tenant domain."""
    rp_id = hostname or tenant_domain
    if not rp_id:
        raise ValueError("hostname or tenant_domain is required")
    if ":" in rp_id:
        rp_id = rp_id.split(":")[0]
    return rp_id


def _normalize_host(value: str | None) -> str | None:
    """Strip scheme/path/port from a host or URL."""
    if not value:
        return None
    host = str(value).strip().lower()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    host = host.split("/")[0]
    if ":" in host:
        host = host.split(":")[0]
    return host or None


def _parse_browser_origin(origin: str | None) -> tuple[str | None, str | None]:
    """Return ``(hostname, origin_url)`` from a browser Origin header."""
    if not origin:
        return None, None
    from urllib.parse import urlparse

    parsed = urlparse(str(origin).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, None
    host = parsed.hostname.lower()
    netloc = host
    if parsed.port and parsed.port not in {80, 443}:
        netloc = f"{host}:{parsed.port}"
    return host, f"{parsed.scheme}://{netloc}"


def _host_ancestors(host: str) -> list[str]:
    """``panel.uln.me`` → ``[panel.uln.me, uln.me]`` (keep ≥2 labels)."""
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return [host]
    return [".".join(parts[i:]) for i in range(0, len(parts) - 1)]


def _tenant_host_set(tenant: Tenant, primary: str) -> set[str]:
    """Return normalized hostnames trusted for this tenant."""
    hosts = {
        _normalize_host(item)
        for item in (getattr(tenant, "domains", None) or [])
        if _normalize_host(item)
    }
    if primary:
        hosts.add(primary)
    return hosts


def _origin_allowed_for_tenant(
    origin_host: str, *, tenant: Tenant, primary: str
) -> bool:
    """Return whether ``origin_host`` belongs to the tenant's domain tree."""
    tenant_hosts = _tenant_host_set(tenant, primary)
    if origin_host in tenant_hosts:
        return True
    origin_parents = set(_host_ancestors(origin_host))
    primary_parents = set(_host_ancestors(primary))
    return bool(origin_parents & (primary_parents | tenant_hosts))


def resolve_webauthn_rp(
    *,
    hostname: str | None = None,
    tenant: Tenant,
    origin: str | None = None,
) -> tuple[str, str]:
    """
    Pick ``(rp_id, expected_origin)`` for WebAuthn ceremonies.

    When the browser sends ``Origin`` (e.g. ``https://panel.uln.me``), use that
    exact host as ``rp_id``. Using a parent domain (``uln.me``) would require
    ``/.well-known/webauthn`` on the parent, which we do not serve.
    """
    primary = _normalize_host(tenant.primary_domain) or "localhost"
    origin_host, origin_url = _parse_browser_origin(origin)

    if (
        origin_host
        and origin_url
        and _origin_allowed_for_tenant(origin_host, tenant=tenant, primary=primary)
    ):
        return origin_host, origin_url

    if origin_host and origin_url:
        # Unknown origin for this tenant — still bind to the page host rather
        # than a parent domain that would fail in the browser.
        return origin_host, origin_url

    return get_rp_id(hostname, primary), tenant.primary_url


def _profile_display_name(profile: Profile | None, fallback: str | None = None) -> str:
    """Build a display name from ProfileDataSchema fields (not a dict)."""
    if not profile or not profile.profile_data:
        return fallback or "user"
    pd = profile.profile_data
    parts = [pd.first_name, pd.last_name]
    name = " ".join(part.strip() for part in parts if part and str(part).strip())
    return name or fallback or "user"


async def register_passkey(
    tenant: Tenant,
    user_data: UserData,
    hostname: str | None = None,
    origin: str | None = None,
) -> dict:
    """Register a new passkey for a user."""
    user = await models.User.get_item(uid=user_data.sub, tenant_id=tenant.uid)
    if not user:
        return

    identifiers = await user.get_identifiers(not_cached=True)
    identifier_username = next(
        (i.identifier for i in identifiers if i.type == models.AuthIdentifier.USERNAME),
        None,
    )
    profile = await Profile.get_by_user_id(tenant_id=tenant.uid, user_id=user.user_id)
    username = identifier_username or user.user_name or user_data.user_name or "user"
    display_name = _profile_display_name(
        profile,
        user.user_name or user_data.user_name or username,
    )

    rp_id, _expected_origin = resolve_webauthn_rp(
        hostname=hostname, tenant=tenant, origin=origin
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=tenant.name,
        user_id=user.user_id.encode(),
        user_name=username,
        user_display_name=display_name,
        timeout=300,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    await models.Credential.create_item({
        "method": models.AuthSecret.WEBAUTHN,
        "secret": texttools.base64url_encode(options.challenge),
        "user_id": user.user_id,
        "tenant_id": tenant.uid,
        "expires_at": datetime.now(timezone.tz) + timedelta(seconds=300),
        "is_active": False,
    })
    return webauthn.helpers.options_to_json_dict(options)


async def verify_registration_passkey(
    tenant: Tenant,
    user: models.User,
    credential: dict,
    hostname: str | None = None,
    origin: str | None = None,
) -> models.Credential | None:
    """Verify and register a passkey credential."""
    cred = await models.Credential.get_query(**{
        "method": models.AuthSecret.WEBAUTHN,
        "user_id": user.user_id,
        "tenant_id": tenant.uid,
        "expires_at_from": datetime.now(timezone.tz),
        "is_active": False,
    }).first_or_none()

    if not cred:
        return None
    challenge = texttools.base64url_decode(cred.secret)

    rp_id, expected_origin = resolve_webauthn_rp(
        hostname=hostname, tenant=tenant, origin=origin
    )
    # Verify registration response and get the verified credential
    verification = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
    )

    # Store the credential ID and public key
    # The verification object contains the credential ID and public key
    credential_id = texttools.base64url_encode(verification.credential_id)
    public_key = verification.credential_public_key

    await models.UserIdentifier.create_item({
        "user_id": user.uid,
        "tenant_id": user.tenant_id,
        "type": models.AuthIdentifier.PASSKEY_ID,
        "identifier": credential_id,
    })

    cred.secret = texttools.base64url_encode(public_key)
    cred.expires_at = None
    cred.is_active = True
    cred.meta_data = cred.meta_data or {}
    cred.meta_data["credential_id"] = credential_id
    cred.meta_data["sign_count"] = int(verification.sign_count)
    cred.last_used_at = datetime.now(timezone.tz)
    return await cred.save()


async def get_webauthn_credentials(user: models.User | None = None) -> list | None:
    """Get WebAuthn credential descriptors for a user."""
    from webauthn.helpers import base64url_to_bytes
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
    )

    if user is None:
        return None
    creds = await user.get_credentials(method=models.AuthSecret.WEBAUTHN)
    if not creds:
        return None
    descriptors: list[PublicKeyCredentialDescriptor] = []
    for cred in creds:
        credential_id = (cred.meta_data or {}).get("credential_id")
        if not credential_id:
            continue
        descriptors.append(
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(credential_id),
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )
        )
    return descriptors or None


def _passkey_auth_challenge_key(challenge: bytes) -> str:
    """Redis key for a pending passkey authentication challenge."""
    return f"passkey:auth:{texttools.base64url_encode(challenge)}"


async def generate_authentication_challenge(
    tenant: Tenant,
    user_id: str | None = None,
    hostname: str | None = None,
    origin: str | None = None,
) -> dict:
    """Generate authentication challenge for passkey."""
    user = (
        await models.User.get_item(uid=user_id, tenant_id=tenant.uid)
        if user_id
        else None
    )
    rp_id, _expected_origin = resolve_webauthn_rp(
        hostname=hostname, tenant=tenant, origin=origin
    )
    auth_options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        timeout=300,
        allow_credentials=await get_webauthn_credentials(user) if user else None,
    )
    await redis.set(
        _passkey_auth_challenge_key(auth_options.challenge),
        tenant.uid,
        ex=300,
    )
    return webauthn.helpers.options_to_json_dict(auth_options)


async def verify_authentication_passkey(
    tenant: Tenant,
    credential: dict,
    hostname: str | None = None,
    origin: str | None = None,
) -> models.User:
    """Verify authentication passkey and return the authenticated user."""
    import json

    response = credential.get("response") or {}
    client_data_b64 = response.get("clientDataJSON")
    if not client_data_b64:
        raise UnauthorizedError(
            error_code="passkey_invalid",
            detail="Missing clientDataJSON",
            message={
                "en": "Passkey response is incomplete.",
                "fa": "پاسخ پس‌کلید ناقص است.",
            },
        )

    try:
        client_data = json.loads(texttools.base64url_decode(client_data_b64))
        challenge = texttools.base64url_decode(client_data["challenge"])
    except Exception as exc:
        raise UnauthorizedError(
            error_code="passkey_invalid",
            detail="Invalid clientDataJSON",
            message={
                "en": "Passkey response is invalid.",
                "fa": "پاسخ پس‌کلید نامعتبر است.",
            },
        ) from exc

    challenge_key = _passkey_auth_challenge_key(challenge)
    # GETDEL makes the authentication challenge single-use under concurrency.
    stored_tenant = await redis.getdel(challenge_key)
    if not stored_tenant:
        raise UnauthorizedError(
            error_code="passkey_challenge_expired",
            detail="Passkey challenge expired",
            message={
                "en": "Passkey challenge expired. Try again.",
                "fa": "مهلت تأیید پس‌کلید تمام شده. دوباره تلاش کنید.",
            },
        )
    stored_tenant_id = (
        stored_tenant.decode() if isinstance(stored_tenant, bytes) else stored_tenant
    )
    if stored_tenant_id != tenant.uid:
        raise UnauthorizedError(
            error_code="passkey_tenant_mismatch",
            detail="Passkey challenge tenant mismatch",
            message={
                "en": "Passkey challenge is not valid for this platform.",
                "fa": "پس‌کلید برای این سامانه معتبر نیست.",
            },
        )

    identifier = await models.UserIdentifier.find_one({
        "type": models.AuthIdentifier.PASSKEY_ID,
        "identifier": credential.get("id"),
        "tenant_id": tenant.uid,
        "is_deleted": False,
    })
    if not identifier:
        raise UnauthorizedError(
            error_code="passkey_not_found",
            detail="Passkey not registered",
            message={
                "en": "This passkey is not registered.",
                "fa": "این پس‌کلید ثبت نشده است.",
            },
        )

    user = await models.User.get_item(uid=identifier.user_id, tenant_id=tenant.uid)
    if not user or user.tenant_id != tenant.uid:
        raise UnauthorizedError(
            error_code="user_not_found",
            detail="User not found",
            message={"en": "User not found.", "fa": "کاربر پیدا نشد."},
        )

    cred = await models.Credential.find_one({
        "user_id": user.uid,
        "tenant_id": user.tenant_id,
        "method": models.AuthSecret.WEBAUTHN,
        "meta_data.credential_id": credential.get("id"),
        "is_active": True,
        "is_deleted": False,
    })
    if not cred:
        raise UnauthorizedError(
            error_code="passkey_not_found",
            detail="Passkey credential not found",
            message={
                "en": "This passkey is not registered.",
                "fa": "این پس‌کلید ثبت نشده است.",
            },
        )

    try:
        public_key_bytes = texttools.base64url_decode(cred.secret)
        rp_id, expected_origin = resolve_webauthn_rp(
            hostname=hostname, tenant=tenant, origin=origin
        )
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=int(
                (cred.meta_data or {}).get("sign_count") or 0
            ),
        )
    except Exception as exc:
        raise UnauthorizedError(
            error_code="passkey_verification_failed",
            detail="Passkey verification failed",
            message={
                "en": "Passkey verification failed.",
                "fa": "تأیید پس‌کلید ناموفق بود.",
            },
        ) from exc

    cred.meta_data = cred.meta_data or {}
    cred.meta_data["sign_count"] = int(verification.new_sign_count)
    cred.last_used_at = datetime.now(timezone.tz)
    await cred.save()
    return user


async def register_random_totp_challenge(
    tenant: Tenant, user_data: UserData, hostname: str | None = None
) -> dict:
    """
    Generate a TOTP secret and QR code for registration.

    Args:
        tenant: The tenant context
        user_data: The user data to register TOTP for
        hostname: Optional hostname for the issuer label

    Returns:
        Dictionary containing:
        - secret: The TOTP secret (base32 string)
        - qr_code: Base64-encoded QR code image
        - provisioning_uri: The TOTP provisioning URI

    """
    # Generate TOTP secret (base32 encoded, 16 bytes = 32 base32 characters)
    totp_secret = pyotp.random_base32()

    # Get user email if available
    user = await models.User.get_item(uid=user_data.sub, tenant_id=tenant.uid)
    if not user:
        raise NotFoundError(
            detail="User not found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )

    user_identifiers = await user.get_identifiers()
    email = next(
        (
            i.identifier
            for i in user_identifiers
            if i.type == models.AuthIdentifier.EMAIL
        ),
        None,
    )
    username = next(
        (
            i.identifier
            for i in user_identifiers
            if i.type == models.AuthIdentifier.USERNAME
        ),
        None,
    )

    # Create TOTP provisioning URI
    # Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}
    issuer = tenant.name or tenant.primary_domain
    account_name = (
        f"{email} ({username})"
        if email and username and email != username
        else email or username or "user"
    )

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=account_name,
        issuer_name=issuer,
    )

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Create image and convert to base64
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    # Store challenge in db (using secret as challenge for verification)
    await models.Credential.create_item({
        "method": models.AuthSecret.TOTP,
        "secret": totp_secret,
        "user_id": user.user_id,
        "tenant_id": user.tenant_id,
        "expires_at": datetime.now(timezone.tz) + timedelta(seconds=300),
        "is_active": False,
    })

    return {
        "secret": totp_secret,
        "qr_code": qr_code_base64,
        "provisioning_uri": provisioning_uri,
    }


async def verify_totp_challenge(
    tenant: Tenant,
    user: models.User,
    data: schemas.TOTPCreateSchema,
    hostname: str | None = None,
) -> models.Credential:
    """Verify TOTP challenge."""
    cred = await models.Credential.get_query(**{
        "method": models.AuthSecret.TOTP,
        "user_id": user.user_id,
        "tenant_id": user.tenant_id,
        "expires_at_from": datetime.now(timezone.tz),
        "is_active": False,
    }).first_or_none()
    if not cred:
        raise BadRequestError(
            error_code="totp_challenge_not_found",
            detail="TOTP challenge not found",
            message={
                "en": "TOTP challenge not found",
                "fa": "درخواست تأیید دو مرحله‌ای پیدا نشد.",
            },
        )
    challenge = cred.secret

    if not services.validate_totp(secret=challenge, code=data.secret):
        raise BadRequestError(
            error_code="totp_challenge_not_valid",
            detail="TOTP challenge not valid",
            message={
                "en": "TOTP challenge not valid",
                "fa": "درخواست تأیید دو مرحله‌ای نامعتبر است.",
            },
        )

    cred.expires_at = data.expires_at
    cred.is_active = True
    cred.last_used_at = datetime.now(timezone.tz)
    return await cred.save()
