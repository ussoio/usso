"""Duplicate user/identifier keys answer with one account-exists message."""

import json
from types import SimpleNamespace

from pymongo.errors import DuplicateKeyError

from server.duplicates import duplicate_key_handler


def _dup(key_pattern: dict) -> DuplicateKeyError:
    return DuplicateKeyError(
        "E11000 duplicate key",
        11000,
        {"keyPattern": key_pattern, "keyValue": {}},
    )


def _request() -> SimpleNamespace:
    return SimpleNamespace(url="https://sso.example.com/api/sso/v1/users", headers={})


def test_identifier_duplicate_is_account_exists() -> None:
    response = duplicate_key_handler(
        _request(), _dup({"tenant_id": 1, "type": 1, "identifier": 1})
    )
    body = json.loads(response.body)
    assert response.status_code == 409
    assert body["error_code"] == "account_already_exists"
    assert "حساب کاربری دیگری" in body["message"]["fa"]


def test_other_duplicates_keep_generic_message() -> None:
    response = duplicate_key_handler(_request(), _dup({"tenant_id": 1, "slug": 1}))
    body = json.loads(response.body)
    assert response.status_code == 409
    assert body["error_code"] == "document_duplicate_key"
