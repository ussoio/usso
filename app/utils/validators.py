"""Shamsi (Jalali) date helpers."""

import re
from datetime import date, datetime
from urllib.parse import urlsplit

from persiantools.digits import fa_to_en
from persiantools.jdatetime import JalaliDate

from server.exceptions import BadRequestError, UnauthorizedError

SHAMSI_DATE_RE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def validate_external_https_url(
    value: str | None,
    *,
    max_length: int = 2048,
) -> str | None:
    """Reject executable, credential-bearing, and non-HTTPS external URLs."""
    if value is None:
        return None
    if len(value) > max_length:
        raise ValueError("URL is too long")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain credentials")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL has an invalid port") from exc
    return value


def validate_date_for_sahmsi(value: date) -> str:
    """Validate and return a yyyy/MM/dd Shamsi date string."""
    return JalaliDate.to_jalali(value).strftime("%Y/%m/%d")


def validate_shamsi_date(value: str) -> JalaliDate:
    """Validate and return a yyyy/MM/dd Shamsi date string."""
    normalized = fa_to_en(value).strip()
    if not SHAMSI_DATE_RE.match(normalized):
        msg = "must be a valid Shamsi date in yyyy/MM/dd format"
        raise ValueError(msg)

    year, month, day = (int(part) for part in normalized.split("/"))
    try:
        return JalaliDate(year, month, day)
    except ValueError as exc:
        msg = "is not a valid Shamsi date"
        raise ValueError(msg) from exc


def normalize_birth_date(value: object) -> tuple[str, date]:
    """
    Normalize birth date to Shamsi text and a Gregorian database value.

    Accepts Shamsi ``yyyy/MM/dd`` or Gregorian ISO ``yyyy-mm-dd`` / ``date``.
    """
    if value is None or value == "":
        raise BadRequestError(
            error_code="invalid_birth_date",
            detail="Birth date is required",
            message={
                "en": "Birth date is required",
                "fa": "تاریخ تولد الزامی است.",
            },
        )

    if isinstance(value, datetime):
        gregorian = value.date()
        return validate_date_for_sahmsi(gregorian), gregorian

    if isinstance(value, date):
        return validate_date_for_sahmsi(value), value

    text = fa_to_en(str(value)).strip()
    try:
        if SHAMSI_DATE_RE.match(text):
            jalali = validate_shamsi_date(text)
            return text, jalali.to_gregorian()
        if ISO_DATE_RE.match(text):
            gregorian = date.fromisoformat(text[:10])
            return validate_date_for_sahmsi(gregorian), gregorian
    except (ValueError, TypeError) as exc:
        raise BadRequestError(
            error_code="invalid_birth_date",
            detail="Birth date must be Shamsi yyyy/MM/dd or Gregorian ISO date",
            message={
                "en": "Birth date must be Shamsi yyyy/MM/dd or Gregorian ISO date",
                "fa": "تاریخ تولد باید شمسی yyyy/MM/dd یا میلادی ISO باشد.",
            },
        ) from exc

    raise BadRequestError(
        error_code="invalid_birth_date",
        detail="Birth date must be Shamsi yyyy/MM/dd or Gregorian ISO date",
        message={
            "en": "Birth date must be Shamsi yyyy/MM/dd or Gregorian ISO date",
            "fa": "تاریخ تولد باید شمسی yyyy/MM/dd یا میلادی ISO باشد.",
        },
    )


def validate_national_code(national_code: str) -> bool:
    """Validate an Iranian national code (کد ملی)."""
    if not national_code.isdigit() or len(national_code) != 10:
        return False

    # Reject codes with all identical digits
    if len(set(national_code)) == 1:
        return False

    check_digit = int(national_code[-1])

    total = sum(int(national_code[i]) * (10 - i) for i in range(9))

    remainder = total % 11

    if remainder < 2:
        return check_digit == remainder

    return check_digit == (11 - remainder)


# Arabic-Indic digits (U+0660..U+0669); persiantools only converts Persian ones.
_ARABIC_INDIC_TO_ASCII = {0x0660 + i: 0x30 + i for i in range(10)}


def validate_organization_code(organization_code: str) -> bool:
    """Validate an organization code (exactly 11 ASCII digits)."""
    return (
        organization_code.isascii()
        and organization_code.isdigit()
        and len(organization_code) == 11
    )


def normalize_organization_code(value: str | None) -> str | None:
    """
    Return the organization code as 11 ASCII digits, or None when absent.

    Persian and Arabic-Indic digits are converted. Raises ValueError when a
    value is present but is not exactly 11 digits.
    """
    if value is None:
        return None
    text = fa_to_en(str(value)).translate(_ARABIC_INDIC_TO_ASCII).strip()
    if not text:
        return None
    if not validate_organization_code(text):
        msg = "organization_code must be exactly 11 digits"
        raise ValueError(msg)
    return text


def validate_phone_national_code_organization_birth_date(
    canonical_phone: str,
    national_code: str,
    organization_code: str,
    birth_date: object,
) -> tuple[str, date]:
    """Validate phone/national/org and normalize birth_date → (shamsi, gregorian)."""
    if not national_code or not validate_national_code(national_code):
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Token does not have valid national code",
            message={
                "en": "Token does not have valid national code",
                "fa": "کد ملی در لینک ورود نامعتبر است.",
            },
        )
    if not canonical_phone:
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Token does not have valid phone",
            message={
                "en": "Token does not have valid phone",
                "fa": "شماره موبایل در لینک ورود نامعتبر است.",
            },
        )
    try:
        shamsi, gregorian = normalize_birth_date(birth_date)
    except BadRequestError as exc:
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Token does not have valid birth date",
            message={
                "en": "Token does not have valid birth date",
                "fa": "تاریخ تولد در لینک ورود نامعتبر است.",
            },
        ) from exc

    if not organization_code or not validate_organization_code(organization_code):
        raise UnauthorizedError(
            error_code="invalid_token",
            detail="Token does not have valid organization code",
            message={
                "en": "Token does not have valid organization code",
                "fa": "کد سازمان در لینک ورود نامعتبر است.",
            },
        )
    return shamsi, gregorian
