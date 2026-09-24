"""Unit tests for tenant secret schemas."""

import pytest
from pydantic import ValidationError

from apps.tenant.secrets import TrustedIdentityProvider


def test_trusted_provider_accepts_public_pem() -> None:
    """Provider can be configured with a PEM key."""
    provider = TrustedIdentityProvider(
        issuer="https://issuer.test",
        public_pem="-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----",
        maximum_age=300,
    )
    assert provider.key == provider.public_pem


def test_trusted_provider_accepts_jwks_url() -> None:
    """Provider can be configured with a JWKS URL."""
    provider = TrustedIdentityProvider(
        issuer="https://issuer.test",
        jwks_url="https://issuer.test/.well-known/jwks.json",
        maximum_age=300,
    )
    assert provider.jwks_url is not None
    assert provider.key is None


def test_trusted_provider_accepts_inline_jwk() -> None:
    """Provider can be configured with an inline JWK."""
    provider = TrustedIdentityProvider(
        issuer="https://issuer.test",
        jwk={"kty": "RSA", "n": "abc", "e": "AQAB"},
        maximum_age=300,
    )
    assert provider.key == {"kty": "RSA", "n": "abc", "e": "AQAB"}


def test_trusted_provider_rejects_multiple_sources() -> None:
    """Provider must have exactly one verification source."""
    with pytest.raises(ValidationError):
        TrustedIdentityProvider(
            issuer="https://issuer.test",
            public_pem="-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----",
            jwks_url="https://issuer.test/.well-known/jwks.json",
            maximum_age=300,
        )


def test_trusted_provider_rejects_missing_sources() -> None:
    """Provider rejects missing verification source."""
    with pytest.raises(ValidationError):
        TrustedIdentityProvider(
            issuer="https://issuer.test",
            maximum_age=300,
        )
