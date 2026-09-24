"""KYC routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from usso import UserData, authorization
from usso.exceptions import PermissionDenied

from apps.identity.kyc import services
from apps.identity.user.models import User
from apps.tenant.services import get_request_tenant
from server.exceptions import (
    BadRequestError,
    NotFoundError,
    UnauthorizedError,
)
from server.rate_limiter import get_rate_limiter

from .models import KYC
from .schemas import KYCCreateSchema, KYCSchema, KYCStatus
from .services import (
    activate_user,
    authenticate_user,
    get_user_phone,
    verify_kyc,
    verify_phone,
)

router = APIRouter(prefix="/kyc", tags=["KYC"])


@router.post("", dependencies=[Depends(get_rate_limiter("/kyc"))])
async def create_kyc(
    request: Request, kyc_data: KYCCreateSchema, redirect: bool = True
) -> KYCSchema:
    """Create a new KYC."""
    tenant = await get_request_tenant(request)
    access_payload = tenant.get_auth("access", raise_exception=False)(request)
    temporary_payload = tenant.temporary_auth(request)
    user_payload = temporary_payload or access_payload
    if user_payload is None:
        raise UnauthorizedError(error_code="unauthorized")
    user_phone = await get_user_phone(user_payload)
    if user_phone is None:
        raise BadRequestError(
            error_code="phone_not_found",
            detail="Phone not found",
            message={
                "en": "Phone not found",
                "fa": "شماره موبایل شما در سیستم ثبت نشده است.",
            },
        )

    if not await verify_phone(kyc_data.national_code, user_phone):
        raise BadRequestError(
            error_code="phone_not_verified",
            detail="Phone and national ID do not match",
            message={
                "en": "Phone number and national ID do not match",
                "fa": "شماره تلفن و کد ملی مطابقت ندارد.",
            },
        )

    civil_data = await services.verify_civil(
        kyc_data.national_code, kyc_data.birth_date_shamsi
    )

    current_user = await User.get_item(
        uid=user_payload.user_id, tenant_id=user_payload.tenant_id
    )
    user = await services.resolve_user_for_national_code(
        current_user=current_user,
        national_code=kyc_data.national_code,
        phone=user_phone,
    )

    kyc = await KYC(
        tenant_id=tenant.uid,
        user_id=user.uid,
        national_code=kyc_data.national_code,
        birth_date=kyc_data.birth_date,
        status=KYCStatus.APPROVED,
        civil_data=civil_data,
    ).save()

    await activate_user(kyc, user)
    response = await authenticate_user(kyc, request, user, user_payload, tenant)
    return response


@router.get("/{user_id}")
async def get_user_kyc(request: Request, user_id: str) -> KYCSchema | None:
    """Get KYC."""
    tenant = await get_request_tenant(request)
    user: UserData = tenant.access_auth(request)

    if authorization.owner_authorization(
        requested_filter={"user_id": user_id},
        self_action="owner",
        action="read",
        **{"user_id": user_id},
    ):
        return (
            await KYC
            .find({"user_id": user_id, "tenant_id": tenant.uid})
            .sort("-created_at")
            .first_or_none()
        )

    user_scopes = user.scopes or []
    if not authorization.check_access(
        user_scopes=user_scopes,
        resource_path="/kyc",
        action="read",
        filters={"user_id": user_id},
    ):
        raise PermissionDenied(detail=f"User {user.uid} is not authorized to read KYC")

    return (
        await KYC
        .find({"user_id": user_id, "tenant_id": tenant.uid})
        .sort("-created_at")
        .first_or_none()
    )


@router.get("/callback/{uid}", include_in_schema=False)
async def callback_kyc(request: Request, uid: str) -> KYCSchema:
    """Verify KYC request on callback."""
    tenant = await get_request_tenant(request)
    temporary_payload = tenant.temporary_auth(request)
    kyc = await KYC.get_item(
        uid=uid,
        tenant_id=temporary_payload.tenant_id,
        user_id=temporary_payload.sub,
    )

    if not kyc:
        raise NotFoundError(
            detail="KYC not found",
            message={
                "en": "Identity verification record not found",
                "fa": "اطلاعات تأیید هویت شما پیدا نشد.",
            },
        )

    if kyc.status != KYCStatus.PENDING:
        raise BadRequestError(
            error_code="kyc_not_pending",
            detail="KYC is not pending",
            message={
                "en": "Your identity verification request is not pending review",
                "fa": "درخواست تأیید هویت شما در انتظار بررسی نیست.",
            },
        )

    if not await verify_kyc(kyc.kyc_id):
        kyc.status = KYCStatus.REJECTED
        await kyc.save()
        return RedirectResponse(url=kyc.return_url)

    kyc.status = KYCStatus.APPROVED
    await kyc.save()

    user = await User.get_item(uid=kyc.user_id, tenant_id=kyc.tenant_id)
    await activate_user(kyc, user)
    await authenticate_user(kyc, request, user, temporary_payload, tenant)

    return RedirectResponse(url=kyc.return_url)
