"""
Captcha API routes.

This module provides endpoints for generating captcha challenges and
verifying captcha responses.
"""

from fastapi import APIRouter, Depends, Request, Response

from apps.tenant.services import get_request_tenant
from server.db import redis
from server.exceptions import BadRequestError
from server.rate_limiter import generate_fingerprint, get_rate_limiter

from .dependencies import _validate_altcha_payload, verify_captcha
from .schemas import ChallengeResponse

router = APIRouter(prefix="/captcha", tags=["Captcha"])


@router.get(
    "/challenge",
    # response_model=ChallengeResponse,  # ruff:ignore[commented-out-code]
    dependencies=[Depends(get_rate_limiter("/captcha/challenge"))],
)
async def get_challenge(request: Request, response: Response) -> dict[str, object]:
    """
    Generate a new captcha challenge.

    Tracks attempts per fingerprint and shows image captcha if attempts
    exceed the tenant's configured threshold. Skips image captcha when a
    valid altcha payload is already present in header or cookie.

    Args:
        request: The FastAPI request object.
        response: The FastAPI response object.

    Returns:
        Dictionary containing the captcha challenge data.

    """
    tenant = await get_request_tenant(request)
    fingerprint = generate_fingerprint(request)
    altcha_payload = request.headers.get("x-altcha-payload") or request.cookies.get(
        "altcha_payload"
    )

    has_trusted_payload = False
    if altcha_payload:
        try:
            # Only check the solved captcha here; do not spend one of its uses.
            await _validate_altcha_payload(
                altcha_payload, fingerprint=fingerprint, count_usage=False
            )
            has_trusted_payload = True
        except BadRequestError:
            pass

    if has_trusted_payload:
        show_image_captcha = False
    else:
        # Track attempts per fingerprint
        key = f"captcha:attempts:{fingerprint}"
        attempts = await redis.incr(key)
        if attempts == 1:
            await redis.expire(key, 3600)

        # The first ``image_captcha_tries`` challenges are PoW only; later
        # ones in the same hour also need the image code.
        show_image_captcha = attempts > tenant.config.image_captcha_tries

        host = request.headers.get("host", "")
        parts = host.split(".")
        domain = "." + ".".join(parts[max(len(parts) - 2, -2) :])
        response.delete_cookie(
            "altcha_payload", domain=domain, samesite="lax", httponly=True, secure=True
        )

    challenge = await ChallengeResponse.get_random_challenge(
        image_captcha=show_image_captcha, fingerprint=fingerprint
    )

    result = challenge.model_dump(exclude_none=True, by_alias=True)
    # Only return altcha-compatible fields
    # (plus codeChallenge when image captcha is active)
    altcha_fields = {
        "algorithm",
        "challenge",
        "maxnumber",
        "salt",
        "signature",
        "codeChallenge",
    }
    return {k: v for k, v in result.items() if k in altcha_fields}


@router.post("/verify")
async def verify(
    request: Request,
    payload: str = Depends(verify_captcha),
) -> dict[str, object]:
    """
    Verify the captcha payload and return status with input data.

    Args:
        request: The FastAPI request object.
        payload: Verified captcha payload from dependency.

    Returns:
        Dictionary with verification status and message.

    """
    return {
        "verified": True,
        "payload": payload,
        "message": "captcha verified successfully",
        # "altcha_payload": payload,  # ruff:ignore[commented-out-code]
    }
