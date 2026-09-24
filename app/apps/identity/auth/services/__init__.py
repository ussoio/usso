"""Authentication services package."""

from apps.tenant.models import Tenant

from .account_switch import (
    build_browser_login_response,
    list_browser_accounts,
    return_from_impersonation,
    switch_browser_account,
)
from .basics import (
    get_tenant_url,
    sanitize_origin,
)
from .login_flow import (
    process_login_flow,
    register_new_user,
    resolve_login_attempt,
    validate_flow_completion,
)
from .magic_link import consume_magic_link, magic_link_payload
from .message import (
    check_otp_needed_and_send,
    create_otp,
    send_magic_link,
)
from .oauth import (
    create_oauth_credential,
    create_oauth_session,
    exchange_oauth_code_for_userinfo,
    resolve_oauth_identity,
    sanitize_return_url,
)
from .qr_login import (
    approve_qr_session,
    claim_approved_qr_user,
    create_qr_session,
    get_qr_session_status,
)
from .secure_token import (
    create_secure_token_payload,
    extract_secure_token,
    is_secure_amr,
    is_secure_method,
    maybe_attach_secure_token,
    require_secure_token,
)
from .telegram import (
    TelegramIdTokenSchema,
    build_telegram_login_request,
    require_telegram_oauth,
    telegram_display_name,
    telegram_user_id_from_claims,
    verify_telegram_id_token,
)
from .token import (
    build_login_response,
    build_refresh_response,
    build_workspace_switch_response,
    check_session_validity,
    create_token_response,
    remove_auth_cookies,
)

__all__ = [
    "TelegramIdTokenSchema",
    "Tenant",
    "approve_qr_session",
    "build_browser_login_response",
    "build_login_response",
    "build_refresh_response",
    "build_telegram_login_request",
    "build_workspace_switch_response",
    "check_otp_needed_and_send",
    "check_session_validity",
    "claim_approved_qr_user",
    "consume_magic_link",
    "create_oauth_credential",
    "create_oauth_session",
    "create_otp",
    "create_qr_session",
    "create_secure_token_payload",
    "create_token_response",
    "exchange_oauth_code_for_userinfo",
    "extract_secure_token",
    "get_qr_session_status",
    "get_tenant_url",
    "is_secure_amr",
    "is_secure_method",
    "list_browser_accounts",
    "magic_link_payload",
    "maybe_attach_secure_token",
    "process_login_flow",
    "register_new_user",
    "remove_auth_cookies",
    "require_secure_token",
    "require_telegram_oauth",
    "resolve_login_attempt",
    "resolve_oauth_identity",
    "return_from_impersonation",
    "sanitize_origin",
    "sanitize_return_url",
    "send_magic_link",
    "switch_browser_account",
    "telegram_display_name",
    "telegram_user_id_from_claims",
    "validate_flow_completion",
    "verify_telegram_id_token",
]
