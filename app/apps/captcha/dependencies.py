"""
Captcha verification dependencies.

This module provides FastAPI dependencies for verifying captcha payloads
from request bodies, cookies, or headers.
"""

from fastapi import Body, Request, Response

from server.exceptions import BadRequestError
from server.rate_limiter import generate_fingerprint

from .schemas import ValidationRequest

# Error message constants
ALTCHA_PAYLOAD_REQUIRED = "altcha header or cookie is required"
ALTCHA_INVALID = "Invalid challenge"
ALTCHA_EXPIRED = "Expired challenge"
ALTCHA_INVALID_SIGNATURE = "Invalid signature"

_CAPTCHA_ERROR_FA: dict[str, str] = {
    ALTCHA_INVALID: "کپچا تأیید نشد. دوباره تکمیل کنید.",
    ALTCHA_EXPIRED: "مهلت کپچا تمام شده. صفحه را دوباره بارگذاری کنید.",
    ALTCHA_INVALID_SIGNATURE: "کپچا تأیید نشد. دوباره تکمیل کنید.",
    "Invalid algorithm": "کپچا تأیید نشد. دوباره تکمیل کنید.",
    "Invalid code": "حروف تصویر اشتباه است.",
    "Captcha used too many times": (
        "این کپچا دیگر قابل استفاده نیست. صفحه را دوباره بارگذاری کنید."
    ),
}


def _captcha_error_fa(verify_error_msg: str) -> str:
    return _CAPTCHA_ERROR_FA.get(verify_error_msg, "کپچا تأیید نشد. دوباره تکمیل کنید.")


async def _validate_altcha_payload(
    altcha_payload: str | None,
    code: str | None = None,
    fingerprint: str = "",
    *,
    count_usage: bool = True,
) -> ValidationRequest:
    """
    Validate altcha payload and code.

    Args:
        altcha_payload: The ALTCHA payload string to validate.
        code: Optional captcha code to validate.
        fingerprint: Client fingerprint for code validation.
        count_usage: Whether to increment and enforce usage limits.

    Returns:
        ValidationRequest instance if validation succeeds.

    Raises:
        ResourceError: If payload is missing or validation fails.

    """
    if not altcha_payload:
        raise BadRequestError(
            error_code="captcha_error",
            detail="Captcha payload is required",
            message={
                "en": "Captcha payload is required",
                "fa": "لطفاً کپچای صفحه را تکمیل کنید.",
            },
        )

    try:
        data = ValidationRequest(altcha_payload=altcha_payload)
        verify_error_msg = await data.validate_error(
            code=code, fingerprint=fingerprint, count_usage=count_usage
        )
    except ValueError:
        raise BadRequestError(
            error_code="captcha_error",
            detail=ALTCHA_INVALID,
            message={
                "en": ALTCHA_INVALID,
                "fa": "کپچا تأیید نشد. دوباره تکمیل کنید.",
            },
        ) from None
    if verify_error_msg:
        raise BadRequestError(
            error_code="captcha_error",
            detail=verify_error_msg,
            message={
                "en": verify_error_msg,
                "fa": _captcha_error_fa(verify_error_msg),
            },
        )

    return data


def _set_cookie(request: Request, response: Response, altcha_payload: str) -> None:
    response.set_cookie(
        "altcha_payload",
        altcha_payload,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return response


async def verify_captcha(
    request: Request,
    response: Response,
    payload: str | None = Body(default=None, embed=True, alias="payload"),
    code: str | None = Body(default=None, embed=True),
) -> str:
    """
    Dependency to verify altcha captcha payload from body, cookie, or header.

    Raises HTTPException with proper error message if invalid.
    """
    payload = (
        payload
        or request.headers.get("x-altcha-payload")
        or request.cookies.get("altcha_payload")
    )
    fingerprint = generate_fingerprint(request)

    validation = await _validate_altcha_payload(
        payload, code=code, fingerprint=fingerprint
    )
    altcha_payload = validation.get_cookie_payload(code=code)
    if validation.should_set_cookie:
        _set_cookie(request, response, altcha_payload)

    return altcha_payload


async def check_captcha(request: Request, response: Response) -> Response:
    """
    Dependency to verify altcha captcha payload from cookie or header.

    Checks cookies and headers for captcha payload. Sets cookie if validation
    succeeds and cookie should be set.

    Args:
        request: The FastAPI request object.
        response: The FastAPI response object.

    Returns:
        Response object with cookie set if validation succeeds.

    Raises:
        ResourceError: If payload is missing or validation fails.

    """
    altcha_payload = request.headers.get("x-altcha-payload") or request.cookies.get(
        "altcha_payload"
    )

    validation = await _validate_altcha_payload(altcha_payload)
    if validation.should_set_cookie:
        _set_cookie(request, response, validation.get_cookie_payload())

    return response
