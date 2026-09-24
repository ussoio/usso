"""KYC services."""

from datetime import datetime
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi_mongo_base.errors import BaseHTTPException
from fastapi_mongo_base.utils import basic, timezone
from usso import UserData
from usso.user import TokenType

from apps.identity.auth.enums import LoginStatus
from apps.identity.auth.schemas import LoginFlowResult, PayloadData
from apps.identity.auth.services import create_token_response
from apps.identity.auth.services.token import (
    attach_auth_cookies_to_response,
    is_cookie_auth_preferred,
)
from apps.identity.user.models import AuthIdentifier, User, UserIdentifier
from apps.tenant.models import Tenant
from server.exceptions import ServiceUnavailableError

from .models import KYC
from .provider import get_kyc_provider
from .schemas import CreateKycResponse


def _civil_payload(civil_data: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize civil-registry payloads that may wrap fields under ``data``."""
    if not isinstance(civil_data, dict):
        return {}
    nested = civil_data.get("data")
    if isinstance(nested, dict):
        return nested
    return civil_data


def civil_name_parts(
    civil_data: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Extract first/last name from a civil-registry payload."""
    data = _civil_payload(civil_data)
    first = data.get("firstName") or data.get("first_name")
    last = data.get("lastName") or data.get("last_name")
    return (
        str(first).strip() or None if first is not None else None,
        str(last).strip() or None if last is not None else None,
    )


@basic.debug_mode_mock({
    "success": True,
    "data": {
        "nationalId": "1111111111",
        "birthDate": "1370/01/01",
        "firstName": "محمد",
        "lastName": "محمدی",
        "fatherName": "احمد",
        "identificationNo": "1111111111",
        "identificationSeries": "د01",
        "identificationSerial": "111111",
        "officeName": "تهران - نمونه",
        "deathStatusStr": "در قید حیات",
        "deathStatus": "ALIVE",
        "gender": "مرد",
    },
})
async def verify_civil(national_code: str, birth_date_shamsi: str) -> dict:
    """Verify national code and birth date via the configured KYC provider."""
    try:
        return await get_kyc_provider().verify_civil(national_code, birth_date_shamsi)
    except BaseHTTPException:
        raise
    except Exception as exc:
        raise ServiceUnavailableError(
            error_code="verification_service_error",
            detail="Civil verification is temporarily unavailable",
            message={
                "en": "Civil verification is temporarily unavailable",
                "fa": "فعلاً امکان اتصال به سامانه ثبت احوال وجود ندارد.",
            },
        ) from exc


@basic.debug_mode_mock(None)
async def init_kyc(national_code: str, phone: str) -> dict:
    """Create a new KYC session via the configured provider."""
    return await get_kyc_provider().init_kyc(national_code, phone)


@basic.debug_mode_mock(True)
async def verify_kyc(kyc_id: str) -> bool:
    """Verify a KYC session via the configured provider."""
    return await get_kyc_provider().verify_kyc(kyc_id)


@basic.debug_mode_mock(True)
async def verify_phone(national_code: str, phone: str) -> bool:
    """Verify phone ownership via the configured KYC provider."""
    if phone.startswith("98"):
        phone = f"0{phone[2:]}"
    return await get_kyc_provider().verify_phone(national_code, phone)


async def attach_phone_to_user(
    *,
    tenant_id: str,
    target_user_id: str,
    phone: str,
    source_user_id: str | None = None,
) -> None:
    """
    Ensure ``phone`` is linked to ``target_user_id``.

    When the phone identifier currently belongs to ``source_user_id``, reassign
    it instead of creating a duplicate row. If the target already owns the
    phone, soft-delete the source copy so the ephemeral user is emptied.
    """
    existing_on_target = await UserIdentifier.find_one({
        "tenant_id": tenant_id,
        "user_id": target_user_id,
        "type": AuthIdentifier.PHONE,
        "identifier": phone,
        "is_deleted": False,
    })

    if source_user_id and source_user_id != target_user_id:
        source_phone = await UserIdentifier.find_one({
            "tenant_id": tenant_id,
            "user_id": source_user_id,
            "type": AuthIdentifier.PHONE,
            "identifier": phone,
            "is_deleted": False,
        })
        if source_phone is not None:
            if existing_on_target is not None:
                source_phone.is_deleted = True
                await source_phone.save()
            else:
                source_phone.user_id = target_user_id
                await source_phone.save()
            return

    if existing_on_target is not None:
        return

    await UserIdentifier(
        tenant_id=tenant_id,
        user_id=target_user_id,
        type=AuthIdentifier.PHONE,
        identifier=phone,
        verified_at=datetime.now(timezone.tz),
        is_primary=False,
        is_active=True,
    ).save()


async def retire_orphaned_merge_source(*, source_user: User) -> None:
    """
    Deactivate and soft-delete a shell user left after national-id phone merge.

    OTP login often creates a phone-only user; after the phone is moved onto an
    existing national-id account, the empty shell must not remain listed.
    """
    remaining = await UserIdentifier.find_one({
        "tenant_id": source_user.tenant_id,
        "user_id": source_user.uid,
        "is_deleted": False,
    })
    if remaining is not None:
        return

    source_user.is_active = False
    await source_user.save()
    await User.delete_item(source_user)


async def resolve_user_for_national_code(
    *,
    current_user: User,
    national_code: str,
    phone: str,
) -> User:
    """
    Return the account that owns ``national_code``.

    If the national ID already belongs to a different user, attach the current
    phone to that older account, retire the emptied phone-only shell, and
    continue KYC against the older account.
    """
    existing_national = await UserIdentifier.find_one({
        "tenant_id": current_user.tenant_id,
        "type": AuthIdentifier.NATIONAL_ID,
        "identifier": national_code,
        "is_deleted": False,
    })
    target_user_id = existing_national.user_id if existing_national else None

    if target_user_id is None:
        existing_kyc = await KYC.get_by_national_code(
            national_code, current_user.tenant_id
        )
        if existing_kyc is not None:
            target_user_id = existing_kyc.user_id

    if target_user_id is None or target_user_id == current_user.uid:
        return current_user

    target_user = await User.get_item(
        uid=target_user_id, tenant_id=current_user.tenant_id
    )
    if target_user is None:
        return current_user

    await attach_phone_to_user(
        tenant_id=current_user.tenant_id,
        target_user_id=target_user.uid,
        phone=phone,
        source_user_id=current_user.uid,
    )
    await retire_orphaned_merge_source(source_user=current_user)
    return target_user


async def activate_user(kyc: KYC, user: User) -> User:
    """Activate the user and attach verified national ID after successful KYC."""
    # Add national_id as verified identifier if not already present
    existing_national_id = await UserIdentifier.find_one({
        "tenant_id": user.tenant_id,
        "user_id": user.uid,
        "type": AuthIdentifier.NATIONAL_ID,
        "identifier": kyc.national_code,
    })
    if not existing_national_id:
        national_id_identifier = UserIdentifier(
            tenant_id=user.tenant_id,
            user_id=user.uid,
            type=AuthIdentifier.NATIONAL_ID,
            identifier=kyc.national_code,
            verified_at=datetime.now(timezone.tz),
            is_primary=False,
            is_active=True,
        )
        await national_id_identifier.save()

    first_name, last_name = civil_name_parts(kyc.civil_data)
    display_name = " ".join(part for part in (first_name, last_name) if part)
    if display_name and not user.name:
        user.name = display_name

    if first_name or last_name:
        from apps.identity.user.services import upsert_admin_profile

        await upsert_admin_profile(
            user=user, first_name=first_name, last_name=last_name
        )

    user.is_active = True
    user.roles.append("user")
    user.roles = list(set(user.roles))

    return await user.save()


async def authenticate_user(
    kyc: KYC,
    request: Request,
    user: User,
    user_payload: UserData,
    tenant: Tenant,
) -> Response:
    """Issue auth tokens and build the KYC completion response."""
    login_flow_result = LoginFlowResult(
        status=LoginStatus.COMPLETED, user=user, amr=user_payload.amr
    )
    payloads = await create_token_response(
        user=login_flow_result.user,
        tenant=tenant,
        login_flow_result=login_flow_result,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host,
        url=request.url,
    )
    return build_kyc_response(
        kyc=kyc,
        request=request,
        tenant=tenant,
        payloads=payloads,
        status=login_flow_result.status,
        domain=request.url.hostname,
    )


def build_kyc_response(
    *,
    kyc: KYC,
    request: Request,
    tenant: Tenant,
    payloads: dict[TokenType, PayloadData],
    status: LoginStatus,
    domain: str | None,
) -> Response:
    """
    Generate a login response for the user.

    Args:
        kyc: The verified KYC record
        request: The incoming request
        tenant: The tenant
        payloads: The token payloads
        status: The status of the login
        domain: Optional domain for cookies

    Returns:
        A response with LoginResponse body and optional cookies

    """
    # Create LoginResponse body
    tokens = {token_type: payload.token for token_type, payload in payloads.items()}

    login_data = CreateKycResponse(
        kyc=kyc,
        status=status,
    )

    if not is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        login_data.tokens = tokens

    # Set the response body
    response = JSONResponse(
        content=login_data.model_dump(mode="json", exclude_none=True),
    )

    # Attach cookies if cookie auth is preferred
    if is_cookie_auth_preferred(
        request=request,
        tenant_cookie=tenant.config.cookie_header_config.header_or_cookie == "cookie",
    ):
        attach_auth_cookies_to_response(
            response=response,
            tenant=tenant,
            payloads=payloads,
            domain=domain or request.url.hostname,
        )

    return response


async def get_user_phone(user_payload: UserData) -> str | None:
    """Get the user's phone number from the user identifier."""
    user_identifier = await UserIdentifier.find_one({
        "tenant_id": user_payload.tenant_id,
        "user_id": user_payload.user_id,
        "type": AuthIdentifier.PHONE,
    })

    return user_identifier.identifier if user_identifier else None
