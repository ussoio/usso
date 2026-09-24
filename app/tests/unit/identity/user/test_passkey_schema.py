"""Unit tests for passkey request schemas."""

import pytest
from pydantic import ValidationError

from apps.identity.user.passkey import PasskeyAssertion


def test_passkey_registration_accepts_attestation_object_only() -> None:
    payload = PasskeyAssertion.model_validate({
        "type": "public-key",
        "id": "cred-id",
        "rawId": "cred-id",
        "response": {
            "clientDataJSON": "Y2Q=",
            "attestationObject": "YW8=",
        },
    })
    assert payload.response.attestationObject == "YW8="
    assert payload.response.authenticatorData is None


def test_passkey_authentication_requires_authenticator_data_and_signature() -> None:
    payload = PasskeyAssertion.model_validate({
        "type": "public-key",
        "id": "cred-id",
        "rawId": "cred-id",
        "response": {
            "clientDataJSON": "Y2Q=",
            "authenticatorData": "YWQ=",
            "signature": "c2ln",
        },
    })
    assert payload.response.signature == "c2ln"


def test_passkey_rejects_incomplete_response() -> None:
    with pytest.raises(ValidationError):
        PasskeyAssertion.model_validate({
            "type": "public-key",
            "id": "cred-id",
            "rawId": "cred-id",
            "response": {"clientDataJSON": "Y2Q="},
        })
