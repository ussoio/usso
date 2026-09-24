"""Per-key salt generation and legacy tenant-key migration tests."""

import pytest
from pydantic import ValidationError
from usso_jwt.enums import Algorithm

from apps.tenant.keys import TenantKey
from apps.tenant.secrets import TenantSecrets


def test_random_tenant_keys_have_independent_salts_and_can_decrypt() -> None:
    first = TenantKey.create_random_key(alg=Algorithm.ES256)
    second = TenantKey.create_random_key(alg=Algorithm.ES256)

    assert first.pass_salt
    assert second.pass_salt
    assert first.pass_salt != second.pass_salt
    assert first.get_key() is not None
    assert second.get_key() is not None


def test_legacy_tenant_salt_is_migrated_into_each_key() -> None:
    original = TenantKey.create_random_key(alg=Algorithm.ES256)
    legacy_key = original.model_dump()
    legacy_key.pop("pass_salt")

    migrated = TenantSecrets.model_validate({
        "pass_salt": original.pass_salt,
        "keys": [legacy_key],
    })

    assert migrated.keys[0].pass_salt == original.pass_salt
    assert migrated.keys[0].get_key() is not None
    serialized = migrated.model_dump()
    assert "pass_salt" not in serialized
    assert serialized["keys"][0]["pass_salt"] == original.pass_salt


def test_key_without_per_key_or_legacy_salt_fails_closed() -> None:
    original = TenantKey.create_random_key()
    invalid_key = original.model_dump()
    invalid_key.pop("pass_salt")

    with pytest.raises(ValidationError, match="missing its pass_salt"):
        TenantSecrets.model_validate({"keys": [invalid_key]})
