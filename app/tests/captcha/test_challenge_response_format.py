"""
Tests for captcha challenge response format (Task 1.2).

Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6

These tests verify that the ChallengeResponse model serialization and
the route's field-filtering logic produce ALTCHA-compliant JSON responses
with correct field names and without internal fields.
"""

import pytest

from apps.captcha.schemas import ChallengeResponse

STANDARD_FIELDS = {"algorithm", "challenge", "maxnumber", "salt", "signature"}


# ---------------------------------------------------------------------------
# Helper: simulate the route's field-filtering logic
# ---------------------------------------------------------------------------
def _filter_response(challenge: ChallengeResponse) -> dict:
    """Reproduce the exact filtering logic from the captcha route."""
    result = challenge.model_dump(exclude_none=True, by_alias=True)
    altcha_fields = {
        "algorithm",
        "challenge",
        "maxnumber",
        "salt",
        "signature",
        "codeChallenge",
    }
    return {k: v for k, v in result.items() if k in altcha_fields}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def standard_challenge() -> ChallengeResponse:
    """A standard (non-image) challenge response."""  # ruff:ignore[non-imperative-mood]
    return ChallengeResponse(
        algorithm="SHA-256",
        challenge="abc123hash",
        max_number=100_000,
        salt="somesalt_iat=1000?expires=2000",
        signature="sig123",
        exp=2000,
        iat=1000,
    )


@pytest.fixture
def image_challenge() -> ChallengeResponse:
    """A challenge response with image captcha active."""  # ruff:ignore[non-imperative-mood]
    from apps.captcha.schemas import CodeChallenge

    return ChallengeResponse(
        algorithm="SHA-256",
        challenge="abc123hash",
        max_number=100_000,
        salt="somesalt_iat=1000?expires=2000",
        signature="sig123",
        exp=2000,
        iat=1000,
        codeChallenge=CodeChallenge(
            image="data:image/jpeg;base64,AAAA",
            length=5,
        ),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestStandardChallengeResponse:
    """Tests for standard (non-image) captcha challenge responses."""

    def test_contains_exactly_five_fields(
        self, standard_challenge: ChallengeResponse
    ) -> None:
        """
        Standard response must contain exactly the 5 ALTCHA fields.

        **Validates: Requirements 8.1, 8.5**
        """
        data = _filter_response(standard_challenge)
        assert set(data.keys()) == STANDARD_FIELDS

    def test_exp_excluded(self, standard_challenge: ChallengeResponse) -> None:
        """
        The 'exp' field must not appear in the response.

        **Validates: Requirement 8.2**
        """
        data = _filter_response(standard_challenge)
        assert "exp" not in data

    def test_iat_excluded(self, standard_challenge: ChallengeResponse) -> None:
        """
        The 'iat' field must not appear in the response.

        **Validates: Requirement 8.3**
        """
        data = _filter_response(standard_challenge)
        assert "iat" not in data

    def test_number_excluded(self, standard_challenge: ChallengeResponse) -> None:
        """
        The 'number' field (the secret solution) must not appear in the response.

        **Validates: Requirement 8.4**
        """
        data = _filter_response(standard_challenge)
        assert "number" not in data

    def test_maxnumber_key_is_camelcase(
        self, standard_challenge: ChallengeResponse
    ) -> None:
        """
        The max-number field must be serialized as 'maxnumber' (no underscore).

        **Validates: Requirement 8.1**
        """
        data = _filter_response(standard_challenge)
        assert "maxnumber" in data, "'maxnumber' key must be present"
        assert "max_number" not in data, "'max_number' must not appear"


class TestImageCaptchaResponse:
    """Tests for image captcha challenge responses."""

    def test_includes_code_challenge(self, image_challenge: ChallengeResponse) -> None:
        """
        When image captcha is active, codeChallenge must be present.

        **Validates: Requirement 8.6**
        """
        data = _filter_response(image_challenge)
        assert "codeChallenge" in data

    def test_code_challenge_has_image_and_length(
        self, image_challenge: ChallengeResponse
    ) -> None:
        """
        CodeChallenge must contain 'image' and 'length' sub-fields.

        **Validates: Requirement 8.6**
        """
        data = _filter_response(image_challenge)
        cc = data["codeChallenge"]
        assert "image" in cc, "'image' must be in codeChallenge"
        assert "length" in cc, "'length' must be in codeChallenge"
        assert isinstance(cc["image"], str)
        assert isinstance(cc["length"], int)

    def test_has_six_top_level_fields(self, image_challenge: ChallengeResponse) -> None:
        """
        Image captcha response must have exactly 6 keys (5 standard + codeChallenge).

        **Validates: Requirements 8.5, 8.6**
        """
        data = _filter_response(image_challenge)
        expected = STANDARD_FIELDS | {"codeChallenge"}
        assert set(data.keys()) == expected

    def test_standard_fields_still_present(
        self, image_challenge: ChallengeResponse
    ) -> None:
        """
        All 5 standard ALTCHA fields must still be present with image captcha.

        **Validates: Requirement 8.5**
        """
        data = _filter_response(image_challenge)
        for field in STANDARD_FIELDS:
            assert field in data, f"'{field}' must be present even with image captcha"

    def test_exp_iat_number_excluded_with_image(
        self, image_challenge: ChallengeResponse
    ) -> None:
        """
        Internal fields must be excluded even when image captcha is active.

        **Validates: Requirements 8.2, 8.3, 8.4**
        """
        data = _filter_response(image_challenge)
        for excluded in ("exp", "iat", "number"):
            assert excluded not in data, f"'{excluded}' must not be in the response"
