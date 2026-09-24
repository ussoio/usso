"""Login flow service."""

from datetime import datetime

from fastapi_mongo_base.utils import timezone
from usso.utils import validators

from server.exceptions import (
    BadRequestError,
    BaseHTTPException,
    ForbiddenError,
    UnauthorizedError,
)

from ....tenant.models import Tenant
from ...referral.models import ReferralCode
from ...user.models import User
from ...user.services import (
    authenticate_user,
    create_user,
    find_user,
)
from ..enums import (
    AuthFlow,
    AuthIdentifier,
    AuthSecret,
    AuthStep,
    LoginStatus,
    OTPDeliveryStatus,
)
from ..schemas import (
    Identifier,
    LoginAttemptResult,
    LoginFlowResult,
    LoginRequest,
    PayloadData,
)


async def check_referral_code(
    *, referral_code: str | None, tenant_id: str
) -> tuple[ReferralCode | None, ForbiddenError | None]:
    """
    Check if the referral code is valid.

    Return the referral code object or an error.
    """
    from apps.identity.referral.services import extract_referral_code

    referral_code = extract_referral_code(referral_code)

    if not referral_code:
        return None, ForbiddenError(
            detail="Registration requires an invitation code",
            message={
                "en": "Registration requires an invitation code",
                "fa": "برای ثبت‌نام به کد دعوت نیاز دارید.",
            },
        )

    # Validate referral code
    referral = await ReferralCode.get_by_code(code=referral_code, tenant_id=tenant_id)

    if not referral:
        return None, ForbiddenError(
            detail="Invalid or expired invitation code",
            message={
                "en": "Invalid or expired invitation code",
                "fa": "کد دعوت نامعتبر است یا منقضی شده.",
            },
        )

    # Check if referral code is active
    if not referral.is_active:
        return None, ForbiddenError(
            detail="This invitation code is no longer active",
            message={
                "en": "This invitation code is no longer active",
                "fa": "این کد دعوت دیگر قابل استفاده نیست.",
            },
        )

    # Check if referral code has expired
    if referral.expires_at and referral.expires_at < datetime.now(timezone.tz):
        return None, ForbiddenError(
            detail="This invitation code has expired",
            message={
                "en": "This invitation code has expired",
                "fa": "مهلت استفاده از این کد دعوت تمام شده.",
            },
        )

    # Check if referral code has exceeded max usage
    if referral.max_usage is not None and referral.usage_count >= referral.max_usage:
        return None, ForbiddenError(
            detail="This invitation code has reached its maximum usage limit",
            message={
                "en": "This invitation code has reached its maximum usage limit",
                "fa": "ظرفیت استفاده از این کد دعوت پر شده.",
            },
        )

    return referral, None


async def _reserve_registration_referral(
    referral: ReferralCode | None,
    *,
    required: bool,
) -> ReferralCode | None:
    """Atomically reserve a checked referral, failing closed when required."""
    if referral is None:
        return None

    from apps.identity.referral.services import consume_referral_code

    if await consume_referral_code(referral):
        return referral
    if required:
        raise ForbiddenError(
            error_code="referral_unavailable",
            detail="Invalid, expired, or exhausted invitation code",
        )
    return None


async def _create_user_with_referral_reservation(
    *,
    login_request: LoginRequest,
    tenant: Tenant,
    create_kwargs: dict[str, object],
    reserved_referral: ReferralCode | None,
) -> User | None:
    """Create a user and return a referral reservation if creation fails."""
    try:
        user = await create_user(
            login=login_request,
            tenant=tenant,
            **create_kwargs,
        )
    except Exception:
        if reserved_referral:
            from apps.identity.referral.services import release_referral_code

            await release_referral_code(reserved_referral)
        raise

    if user is None and reserved_referral:
        from apps.identity.referral.services import release_referral_code

        await release_referral_code(reserved_referral)
    return user


async def register_new_user(
    *, login_request: LoginRequest, tenant: Tenant, **kwargs: object
) -> User | None:
    """
    Register a new user and return the user object.

    This function only handles user creation. The login flow logic
    is handled by process_login_flow to maintain separation of concerns.

    Args:
        login_request: The login request containing identifier and secret
        tenant: The tenant context
        **kwargs: Optional user fields (e.g. name) and auth flags
            (e.g. telegram_verified); only user fields are passed to create_user

    Returns:
        The newly created user

    Raises:
        BaseHTTPException: If registration is not allowed or invite-only check fails

    """
    # Check if registration is allowed
    if not tenant.config.registration.is_allowed:
        return None

    # A new account must never make an externally verified method true merely
    # by naming that method in /auth/login. Password is the only credential a
    # caller may establish directly. OTP registration has already created the
    # pending user when the code was issued; OAuth, magic-link and Telegram are
    # admitted only by their dedicated routes after cryptographic validation.
    trusted_registration_flags = {
        AuthSecret.OAUTH: "oauth_verified",
        AuthSecret.MAGIC_LINK: "magic_link_verified",
        AuthSecret.TELEGRAM_TOKEN: "telegram_verified",
    }
    required_flag = trusted_registration_flags.get(login_request.method)
    method_is_trusted = login_request.method == AuthSecret.PASSWORD or (
        required_flag is not None and kwargs.get(required_flag) is True
    )
    if not method_is_trusted:
        raise UnauthorizedError(
            error_code="unverified_registration_method",
            detail="Registration method has not been verified",
            message={
                "en": "Complete the verified sign-in flow before registering.",
                "fa": "برای ثبت‌نام ابتدا فرایند ورود تأییدشده را کامل کنید.",
            },
        )

    # Check invite-only registration
    referral, error = await check_referral_code(
        referral_code=login_request.referral_code, tenant_id=tenant.uid
    )
    if tenant.config.registration.invite_only and error:
        raise error

    if (
        login_request.type == AuthIdentifier.USERNAME
        and login_request.identifier.lower() in validators.reserved
    ):
        raise BadRequestError(
            error_code="invalid_username",
            detail="Username is reserved",
            message={
                "en": "Username is reserved",
                "fa": "این نام کاربری قابل انتخاب نیست.",
            },
        )

    # Reserve the invitation atomically before creating the account. Without this,
    # concurrent registrations can all pass the read check and exceed max_usage.
    reserved_referral = await _reserve_registration_referral(
        referral,
        required=tenant.config.registration.invite_only,
    )

    # Create new user (auth-only kwargs like telegram_verified must not reach User())
    create_kwargs = {
        key: value
        for key, value in kwargs.items()
        if key in {"name", "is_active", "avatar_url", "custom_claims"}
    }
    user = await _create_user_with_referral_reservation(
        login_request=login_request,
        tenant=tenant,
        create_kwargs=create_kwargs,
        reserved_referral=reserved_referral,
    )
    if user is None:
        return None

    # Notify tenant webhooks only after the reservation and registration succeed.
    if reserved_referral:
        from apps.identity.referral.services import on_referral_registration

        on_referral_registration(
            tenant=tenant,
            referral=reserved_referral,
            invitee=user,
        )

    return user


async def verify_identifier(*, user: User, login_request: LoginRequest) -> bool:
    """
    Verify if the user's identifier can be verified.

    This function checks if the authentication method in the login request matches
    the user's current identifier type. If they match, it marks the identifier as
    verified by setting the verified_at timestamp.

    Args:
        user: The user whose identifier should be verified
        login_request: The login request containing the authentication method

    Returns:
        True if the identifier was verified or was already verified, False otherwise

    """
    # Check if user has a current identifier
    if not user.current_identifier:
        return False

    # Check if identifier is already verified
    if user.current_identifier.verified_at is not None:
        return True

    # Check if login request has a method
    if not login_request.method:
        return False

    expected_identifier_type = AuthSecret.get_identifier_type(login_request.method)
    if not expected_identifier_type:
        return False

    if user.current_identifier.type != expected_identifier_type:
        return False

    # Mark identifier as verified
    user.current_identifier.verified_at = datetime.now(timezone.tz)
    await user.current_identifier.save()
    return True


async def activate_user_if_eligible(
    *, user: User, tenant: Tenant, login_request: LoginRequest
) -> bool:
    """
    Check if the user should be activated based on their verification status.

    This function evaluates whether a user meets the activation criteria based on:
    1. Current verification status of their identifier
    2. Tenant's registration approval mode configuration
    3. The authentication method used in the current login attempt

    Args:
        user: The user to check for activation eligibility
        tenant: The tenant context with configuration
        login_request: The current login request

    Returns:
        True if the user was activated or is already active, False otherwise

    Note:
        This function only activates users, it doesn't deactivate them.
        The activation logic follows the tenant's approval mode configuration.

    """
    # Check if the current login attempt verifies the identifier
    identifier_verified: bool = await verify_identifier(
        user=user, login_request=login_request
    )

    # If user is already active, no need to check further
    if user.is_active:
        return True

    # Check tenant's approval mode to determine activation criteria
    match tenant.config.registration.approval_mode:
        case "none":
            # No approval required - activate immediately
            if login_request.method:
                user.is_active = True
                await user.save()
                return True

        case "identifier":
            # Identifier verification is sufficient for activation
            # Since we already verified the identifier above, activate the user
            # If identifier is not verified, user cannot be activated
            if not identifier_verified:
                return False

            user.is_active = True
            await user.save()
            return True

        case "manual_review":
            # Admin approval required - don't activate automatically
            # User remains inactive until admin approves
            return False

        case "additional":
            # Activate only when the user has an approved KYC record.
            from apps.identity.kyc.models import KYC

            kyc = await KYC.get_by_user_id(user_id=user.uid, tenant_id=tenant.uid)
            if not kyc:
                return False
            user.is_active = True
            await user.save()
            return True

        case _:
            # Unknown approval mode - don't activate
            return False


def validate_flow_completion(
    *,
    login_flow: AuthFlow,
    amr: list[str],
) -> AuthStep | None:
    """
    Validate the login flow completion and return the next incomplete step.

    Matching algorithm (intentional greedy / first-fit):
    - Steps are AND (sequential) — earlier steps must be satisfied before later ones.
    - Within a step, methods are OR up to ``required_num``.
    - Methods are claimed in step.methods list order and cannot be reused in a
      later step (first match wins). Multipath flows that need a globally
      optimal assignment are not supported; configure unambiguous steps instead.

    Args:
        login_flow: The authentication flow configuration
        amr: List of authentication methods that have been used

    Returns:
        The next step that needs to be completed, or None if all done

    """
    used_methods = set()  # Track methods used across all steps to prevent repetition
    next_step = None

    for step in login_flow.steps:
        # Count how many methods from this step have been used
        # (not used in previous steps)
        used_methods_count = 0

        for method in step.methods:
            # Check if method is in amr and hasn't been used before
            if method in amr and method not in used_methods:
                used_methods_count += 1
                used_methods.add(method)

            # Check if this step is completed (enough methods used)
            if used_methods_count >= step.required_num:
                break
        else:
            # This step is not completed, so it's the next step
            next_step = step
            break

    return next_step


def _determine_otp_delivery(
    step: AuthStep,
) -> dict[str, OTPDeliveryStatus]:
    """Determine OTP delivery without revealing whether an account has a password."""
    otp_methods = {
        AuthSecret.PHONE_OTP,
        AuthSecret.EMAIL_OTP,
    }
    delivery: dict[str, OTPDeliveryStatus] = {}
    has_non_otp = any(m not in otp_methods for m in step.methods)

    for method in step.methods:
        if method not in otp_methods:
            continue
        if has_non_otp:
            delivery[method] = OTPDeliveryStatus.REQUESTABLE
        else:
            delivery[method] = OTPDeliveryStatus.SENT

    return delivery


_LOGIN_FLOW_FAILURES: dict[str, tuple[type[BaseHTTPException], dict[str, str]]] = {
    "invalid_credentials": (
        UnauthorizedError,
        {
            "en": "Incorrect password or verification code.",
            "fa": "رمز عبور یا کد ورود اشتباه است.",
        },
    ),
    "registration_failed": (
        BadRequestError,
        {
            "en": "No account found and registration is not available.",
            "fa": "کاربری با این مشخصات وجود ندارد و امکان ثبت‌نام نیست.",
        },
    ),
    "client_not_found": (
        UnauthorizedError,
        {
            "en": "Client not found.",
            "fa": "شناسه‌ی کلاینت یافت نشد.",
        },
    ),
}


def _raise_login_flow_failed(*, error_code: str, detail: str) -> None:
    exc_cls, message = _LOGIN_FLOW_FAILURES.get(
        error_code,
        (
            UnauthorizedError,
            {"en": "Login failed.", "fa": "ورود انجام نشد."},
        ),
    )
    raise exc_cls(error_code=error_code, detail=detail, message=message)


async def resolve_login_attempt(
    *,
    identifier: Identifier,
    tenant: Tenant,
) -> LoginAttemptResult:
    """
    Resolve a login attempt: identify the user and determine available auth methods.

    This function does NOT authenticate. It only:
    1. Looks up the user by identifier
    2. Checks the tenant login flow for the first required step
    3. Determines OTP delivery status (auto-send vs requestable)

    If the user does not exist and registration is allowed, the attempt still
    succeeds with the same next_step (registration happens at login time).

    Raises:
        BadRequestError: If the identifier cannot be used to start sign-in.

    """
    login_flow = tenant.config.auth.login_flow

    if identifier.type and identifier.type not in login_flow.allowed_identifiers:
        raise BadRequestError(
            error_code="identifier_not_allowed",
            detail="This identifier type is not allowed for this tenant",
            message={
                "en": f"Sign-in with {identifier.type} is not available.",
                "fa": (
                    f"ورود با {identifier.type.fa_name} در این سامانه امکان‌پذیر نیست."
                ),
            },
        )

    user = await find_user(identifier=identifier, tenant_id=tenant.uid, tenant=tenant)

    next_step = validate_flow_completion(login_flow=login_flow, amr=[])
    if not next_step:
        raise BadRequestError(
            error_code="invalid_flow",
            detail="Login flow has no steps configured",
            message={
                "en": "Sign-in cannot continue. Please contact support.",
                "fa": "امکان ادامه‌ی ورود وجود ندارد. با پشتیبانی تماس بگیرید.",
            },
        )

    otp_delivery = _determine_otp_delivery(next_step)

    return LoginAttemptResult(
        status=LoginStatus.CHALLENGE_REQUIRED,
        user=user,
        next_step=next_step,
        otp_delivery=otp_delivery,
    )


async def process_login_flow(
    *,
    login_request: LoginRequest,
    tenant: Tenant,
    temporary_payload: PayloadData | None = None,
    **kwargs: object,
) -> LoginFlowResult:
    """
    Process the complete login flow and return the appropriate result.

    This function handles the complete authentication flow including:
    1. User lookup or registration (based on tenant config)
    2. Authentication
    3. Flow step validation
    4. MFA requirements
    5. Verification requirements and User activation

    Args:
        login_request: The login request containing identifier and secret
        tenant: The tenant context
        temporary_payload: Optional temporary payload (verified) for continuing a flow
        **kwargs: Additional keyword arguments

    Returns:
        LoginFlowResult with the current status and next steps

    Raises:
        UnauthorizedError: For invalid credentials or unknown client.
        BadRequestError: When registration is not available.

    """
    # Every route entering this generic flow must present an explicit method
    # and proof.  Without this guard an existing account could skip
    # authenticate_user simply by omitting ``secret`` while still having the
    # claimed method added to AMR below.
    if login_request.method is None or not login_request.secret:
        _raise_login_flow_failed(
            error_code="invalid_credentials",
            detail="Authentication method and secret are required",
        )

    # Step 1: Find or create user
    user = await find_user(
        identifier=login_request,
        tenant_id=tenant.uid,
        tenant=tenant,
    )

    if not user:
        if login_request.type == AuthIdentifier.CLIENT_ID:
            _raise_login_flow_failed(
                error_code="client_not_found",
                detail="Client not found",
            )
        # User doesn't exist - try to register
        user = await register_new_user(
            login_request=login_request, tenant=tenant, **kwargs
        )
        if not user:
            _raise_login_flow_failed(
                error_code="invalid_credentials",
                detail="Invalid credentials",
            )

        # Note: Referral code usage is now handled in register_new_user
        # for invite-only mode. For non-invite-only mode with optional referral codes,
        # we could handle it here if needed in the future.

    # Step 2: Authenticate existing user
    elif not await authenticate_user(user=user, secret=login_request, **kwargs):
        _raise_login_flow_failed(
            error_code="invalid_credentials",
            detail="Invalid credentials",
        )

    # Let's check if the login will verify the identifier

    # Step 3: Check login flow steps
    login_flow = tenant.config.auth.login_flow

    # Get amr from temporary token or empty list if no token
    amr = (temporary_payload.amr if temporary_payload else []) or []
    amr = list({*amr, login_request.method.value}) if login_request.method else amr

    # Check main login flow completion
    next_step = validate_flow_completion(login_flow=login_flow, amr=amr)
    if next_step:
        return LoginFlowResult(
            status=LoginStatus.MFA_REQUIRED,
            user=user,
            amr=amr,
            next_step=next_step,
        )

    # Step 4: Check MFA requirements if tenant main flow is completed
    if user.mfa_enabled and user.mfa_steps:
        next_step = validate_flow_completion(
            login_flow=user.mfa_steps,
            amr=amr,
        )

    if next_step:
        return LoginFlowResult(
            status=LoginStatus.MFA_REQUIRED,
            user=user,
            amr=amr,
            next_step=next_step,
        )

    # Step 5: Handle verification requirements and user activation
    user_is_active = await activate_user_if_eligible(
        user=user, tenant=tenant, login_request=login_request
    )
    if not user_is_active:
        return LoginFlowResult(
            status=LoginStatus.VERIFICATION_REQUIRED, user=user, amr=amr
        )

    # All steps completed - user is activated
    return LoginFlowResult(status=LoginStatus.COMPLETED, user=user, amr=amr)
