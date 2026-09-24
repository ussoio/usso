"""Focused validation coverage for OAuth integration schemas."""

import pytest
from pydantic import ValidationError

from apps.tenant.integration.schemas import (
    AuthorizationRequestSchema,
    ClientRegistrationRequestSchema,
    ClientUpdateSchema,
    GrantType,
    OAuthClientSchema,
    ResponseType,
    TokenRequestSchema,
)


@pytest.mark.parametrize(
    "value",
    [[], ["callback"], ["ftp://app.test/callback"]],
)
def test_oauth_client_redirect_uri_validator_rejects_invalid_values(
    value: list[str],
) -> None:
    with pytest.raises(ValueError):
        OAuthClientSchema.validate_redirect_uris(value)


def test_oauth_client_redirect_uri_validator_accepts_http_and_https() -> None:
    uris = ["https://app.test/callback", "http://localhost:8000/callback"]
    assert OAuthClientSchema.validate_redirect_uris(uris) is uris


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (None, None),
        ("", None),
        ("openid   profile email", ["openid", "profile", "email"]),
    ],
)
def test_authorization_scope_parser(
    scope: str | None, expected: list[str] | None
) -> None:
    assert AuthorizationRequestSchema.validate_scope(scope) == expected


def test_authorization_request_parses_scope_during_validation() -> None:
    request = AuthorizationRequestSchema(
        response_type=ResponseType.CODE,
        client_id="client",
        redirect_uri="https://app.test/callback",
        scope="openid profile",
    )
    assert request.scope == ["openid", "profile"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"grant_type": GrantType.AUTHORIZATION_CODE, "client_id": "client"},
        {
            "grant_type": GrantType.AUTHORIZATION_CODE,
            "client_id": "client",
            "code": "code",
        },
        {"grant_type": GrantType.REFRESH_TOKEN, "client_id": "client"},
        {"grant_type": GrantType.DEVICE_CODE, "client_id": "client"},
        {
            "grant_type": GrantType.DEVICE_CODE,
            "client_id": None,
            "device_code": "device",
        },
    ],
)
def test_token_request_rejects_missing_grant_specific_parameters(kwargs: dict) -> None:
    with pytest.raises(ValidationError):
        TokenRequestSchema(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "grant_type": GrantType.AUTHORIZATION_CODE,
            "client_id": "client",
            "code": "code",
            "redirect_uri": "https://app.test/callback",
        },
        {
            "grant_type": GrantType.REFRESH_TOKEN,
            "client_id": "client",
            "refresh_token": "refresh",
        },
        {"grant_type": GrantType.CLIENT_CREDENTIALS, "client_id": "client"},
        {
            "grant_type": GrantType.DEVICE_CODE,
            "client_id": "client",
            "device_code": "device",
        },
    ],
)
def test_token_request_accepts_complete_grant_parameters(kwargs: dict) -> None:
    assert TokenRequestSchema(**kwargs).grant_type == kwargs["grant_type"]


def test_client_update_redirect_uri_validator_all_branches() -> None:
    assert ClientUpdateSchema.validate_redirect_uris(None) is None
    with pytest.raises(ValueError):
        ClientUpdateSchema.validate_redirect_uris([])
    with pytest.raises(ValueError):
        ClientUpdateSchema.validate_redirect_uris(["callback"])
    with pytest.raises(ValueError):
        ClientUpdateSchema.validate_redirect_uris(["javascript://app.test/callback"])
    uris = ["https://app.test/callback"]
    assert ClientUpdateSchema.validate_redirect_uris(uris) is uris


@pytest.mark.parametrize(
    "uri",
    ["javascript:alert(1)", "http://app.test/logo.png", "https://u:p@app.test"],
)
def test_client_metadata_rejects_unsafe_urls(uri: str) -> None:
    with pytest.raises(ValidationError):
        ClientRegistrationRequestSchema(
            client_name="client",
            redirect_uris=["https://app.test/callback"],
            logo_uri=uri,
        )
