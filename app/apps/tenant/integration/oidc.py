"""OIDC integration for 3rd party applications."""

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from apps.tenant.services import get_tenant
from server.config import Settings

router = APIRouter(tags=["Integration"])


@router.get("/.well-known/jwks.json")
async def get_jwks(
    request: Request, domain: str | None = None
) -> dict[str, list[dict[str, str | int | None]]]:
    """Get JSON Web Key Set (JWKS) for token verification."""
    tenant = await get_tenant(request, domain=domain)

    keys = [
        key.public_jwk
        for key in tenant.secrets.keys
        if key.public_jwk and key.is_active and key.use == "sig"
    ]

    return {"keys": keys}


@router.get("/.well-known/public-keys.pem")
async def get_jwks_pem(
    request: Request, domain: str | None = None
) -> PlainTextResponse:
    """Get public keys in PEM format for token verification."""
    tenant = await get_tenant(request, domain=domain)
    keys = [
        key.public_pem.strip()
        for key in tenant.secrets.keys
        if key.public_jwk and key.is_active and key.use == "sig"
    ]

    content = "\n\n".join(keys) + "\n"

    return PlainTextResponse(
        content,
        media_type="application/x-pem-file",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get("/.well-known/oauth-authorization-server")
async def get_oauth_authorization_server_metadata(
    request: Request,
) -> dict[str, str | list[str] | bool]:
    """RFC 8414 metadata so MCP agents can discover and register themselves."""
    return await get_openid_configuration(request)


@router.get("/.well-known/openid-configuration")
async def get_openid_configuration(
    request: Request,
) -> dict[str, str | list[str] | bool]:
    """Get OpenID Connect configuration."""
    tenant = await get_tenant(request)

    return {
        "registration_endpoint": (
            f"{tenant.primary_url}{Settings.base_path}/oauth/register"
        ),
        "issuer": tenant.primary_url,
        "jwks_uri": f"{tenant.primary_url}/.well-known/jwks.json",
        "authorization_endpoint": (
            f"{tenant.primary_url}{Settings.base_path}/oauth/authorize"
        ),
        "token_endpoint": f"{tenant.primary_url}{Settings.base_path}/oauth/token",
        "device_authorization_endpoint": (
            f"{tenant.primary_url}{Settings.base_path}/oauth/device_authorization"
        ),
        "userinfo_endpoint": f"{tenant.primary_url}{Settings.base_path}/oauth/userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256", "EdDSA"],
        "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "email",
            "email_verified",
        ],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "code_challenge_methods_supported": ["S256"],
        # Additional OIDC features for better compatibility
        "acr_values_supported": ["usso:acr:1", "usso:acr:2"],
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
        "require_request_uri_registration": False,
        "response_modes_supported": ["query", "fragment", "form_post"],
    }
