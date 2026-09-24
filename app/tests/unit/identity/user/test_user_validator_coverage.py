"""Focused coverage for the synchronous Jibit validation client."""

from unittest.mock import MagicMock, patch

from apps.identity.user import validator


def _client() -> validator.JibitClient:
    return validator.JibitClient(api_key="api-key", secret_key="secret-key")


def test_access_token_refreshes_when_missing_or_expired() -> None:
    client = _client()
    try:
        with patch.object(
            client,
            "refresh",
            side_effect=lambda: setattr(client, "_access_token", "fresh"),
        ) as refresh:
            assert client.access_token == "fresh"
        refresh.assert_called_once_with()

        client._jwt = MagicMock()
        client._jwt.is_temporally_valid.return_value = False
        with patch.object(
            client,
            "refresh",
            side_effect=lambda: setattr(client, "_access_token", "new"),
        ):
            assert client.access_token == "new"
    finally:
        client.close()


def test_access_token_setter_builds_jwt_and_authorization_header() -> None:
    client = _client()
    jwt = MagicMock()
    jwt.is_temporally_valid.return_value = True
    try:
        with (
            patch.object(validator, "JWT", return_value=jwt) as jwt_cls,
            patch.object(validator, "JWTConfig", return_value=MagicMock()),
        ):
            client.access_token = "access-token"
        assert client._access_token == "access-token"
        assert client.headers["Authorization"] == "Bearer access-token"
        assert jwt_cls.call_args.kwargs["token"] == "access-token"
    finally:
        client.close()


def test_refresh_posts_old_tokens_and_installs_new_access_token() -> None:
    client = _client()
    response = MagicMock()
    response.json.return_value = {"accessToken": "new-access"}
    client._access_token = "old-access"
    client.refresh_token = "old-refresh"
    client._jwt = MagicMock()
    client._jwt.is_temporally_valid.return_value = True
    new_jwt = MagicMock()
    new_jwt.is_temporally_valid.return_value = True
    try:
        with (
            patch.object(client, "post", return_value=response) as post,
            patch.object(validator, "JWT", return_value=new_jwt),
            patch.object(validator, "JWTConfig", return_value=MagicMock()),
        ):
            assert client.refresh() is response
        post.assert_called_once_with(
            "/tokens/refresh",
            json={"accessToken": "old-access", "refreshToken": "old-refresh"},
        )
        response.raise_for_status.assert_called_once_with()
        assert client._access_token == "new-access"
    finally:
        client.close()


def test_authenticate_posts_credentials_and_stores_tokens() -> None:
    client = _client()
    response = MagicMock()
    response.json.return_value = {
        "accessToken": "access",
        "refreshToken": "refresh",
    }
    jwt = MagicMock()
    jwt.is_temporally_valid.return_value = True
    try:
        with (
            patch.object(client, "post", return_value=response) as post,
            patch.object(validator, "JWT", return_value=jwt),
            patch.object(validator, "JWTConfig", return_value=MagicMock()),
        ):
            client.authenticate()
        post.assert_called_once_with(
            "/tokens/generate",
            json={"apiKey": "api-key", "secretKey": "secret-key"},
        )
        response.raise_for_status.assert_called_once_with()
        assert client._access_token == "access"
        assert client.refresh_token == "refresh"
    finally:
        client.close()


def test_match_passes_identifiers_and_defaults_missing_result_to_false() -> None:
    client = _client()
    response = MagicMock()
    response.json.side_effect = [{"matched": True}, {}]
    try:
        with patch.object(client, "get", return_value=response) as get:
            assert (
                client.match(phone_number="0912", national_code="001", strict=True)
                is True
            )
            assert client.match(phone_number="0912") is False
        assert get.call_args_list[0].kwargs["params"] == {
            "mobileNumber": "0912",
            "nationalCode": "001",
            "strict": True,
        }
        assert response.raise_for_status.call_count == 2
    finally:
        client.close()
