"""Jibit client."""

import httpx
from usso_jwt import JWT, JWTConfig


class JibitClient(httpx.Client):
    """Jibit client."""

    def __init__(self, *, api_key: str, secret_key: str, **kwargs: object) -> None:
        """Initialize Jibit client."""
        super().__init__(**kwargs)
        # self.base_url = "https://napi.jibit.ir/ide/v1"  # ruff:ignore[commented-out-code]
        self.base_url = "https://napi.jibit.io/ide/v1"
        self.api_key = api_key
        self.secret_key = secret_key
        self._access_token = None
        self._jwt = None
        self.refresh_token = None

    @property
    def access_token(self) -> str | None:
        """Access token."""
        if not self._jwt or not self._jwt.is_temporally_valid():
            self.refresh()

        return self._access_token

    @access_token.setter
    def access_token(self, value: str) -> None:
        """Set access token."""
        self._jwt = JWT(token=value, config=JWTConfig())
        self._access_token = value
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})

    def refresh(self) -> httpx.Response:
        """Refresh access token."""
        response = self.post(
            "/tokens/refresh",
            json={
                "accessToken": self.access_token,
                "refreshToken": self.refresh_token,
            },
        )
        response.raise_for_status()
        auth_data: dict = response.json()
        self.access_token = auth_data.get("accessToken")
        return response

    def authenticate(self) -> None:
        """Authenticate with Jibit."""
        response = self.post(
            "/tokens/generate",
            json={"apiKey": self.api_key, "secretKey": self.secret_key},
        )
        response.raise_for_status()
        auth_data: dict = response.json()
        self.access_token = auth_data.get("accessToken")
        self.refresh_token = auth_data.get("refreshToken")

    def match(
        self,
        *,
        phone_number: str | None = None,
        national_code: str | None = None,
        **kwargs: object,
    ) -> bool:
        """Match phone number or national code."""
        response = self.get(
            "/services/matching",
            params={
                "mobileNumber": phone_number,
                "nationalCode": national_code,
                **kwargs,
            },
        )
        response.raise_for_status()
        return response.json().get("matched", False)
