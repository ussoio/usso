"""Legacy documents stored a text ``searchable``; it must not break loading."""

import pytest

from apps.identity.user import schemas

LEGACY_TEXT = "کاربر تست مرکز مبادله"


@pytest.mark.parametrize(
    ("schema", "extra"),
    [
        (schemas.UserSchema, {"tenant_id": "t"}),
        (
            schemas.UserIdentifierSchema,
            {
                "user_id": "u",
                "tenant_id": "t",
                "type": "phone",
                "identifier": "989120000000",
            },
        ),
    ],
)
def test_text_searchable_falls_back_to_default(
    schema: type, extra: dict[str, str]
) -> None:
    item = schema.model_validate({"searchable": LEGACY_TEXT, **extra})
    assert item.searchable is True


@pytest.mark.parametrize("value", [True, False])
def test_bool_searchable_is_kept(value: bool) -> None:
    user = schemas.UserSchema.model_validate({"tenant_id": "t", "searchable": value})
    assert user.searchable is value
