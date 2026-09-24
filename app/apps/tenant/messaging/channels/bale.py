"""Bale Safir channel."""

from datetime import datetime, timedelta

import httpx
from pydantic import BaseModel

from .base import AbstractChannel


class BaleAuthorizError(Exception):
    """Bale authorization error."""


class BaleSafirConfig(BaseModel):
    """Bale Safir config."""

    client_id: str
    client_secret: str


class BaleSafirAPI(httpx.Client):
    """Bale Safir API."""

    def __init__(self, *, client_id: str, client_secret: str, **kwargs: object) -> None:
        """Initialize the Bale Safir API."""
        super().__init__(base_url="https://safir.bale.ai/api/v2", **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret
        self._last_auth = None
        self._expired_at = None

    @property
    def is_expired(self) -> bool:
        """Check if the access token is expired."""
        if not self._expired_at:
            return True
        return self._expired_at < datetime.now()

    def authenticate(self) -> None:
        """Authenticate the API."""
        if not self.is_expired:
            return
        data = {"grant_type": "client_credentials", "scope": "read"}
        resp = self.post(
            "/auth/token",
            data={
                **data,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        result: dict[str, str | int | None] = resp.json()

        if "access_token" not in result:
            raise BaleAuthorizError("login failed")

        self._access_token = result.get("access_token")
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self._last_auth = datetime.now()
        self._expired_at = datetime.now() + timedelta(
            seconds=int(result.get("expires_in"))
        )
        return

    @property
    def access_token(self) -> str | None:
        """The access token."""
        if self.is_expired:
            return
        return self._access_token

    def send_otp(self, *, phone: str, otp: int) -> httpx.Response:
        """
        Send an OTP to a phone number.

        Args:
            phone: The phone number
            otp: The OTP
        Returns:
            The response from the API.

        """
        resp = self.post("/send_otp", json={"phone": phone, "otp": otp})
        return resp


class BaleSafirChannel(AbstractChannel):
    """Bale Safir channel."""

    channel_type = "bale"
    supports_phone = True
    ConfigType = BaleSafirConfig

    def send(self, *, to: str, otp: int, **kwargs: object) -> dict:
        """
        Send an OTP to a phone number.

        Args:
            to: The phone number
            otp: The OTP
            **kwargs: Additional arguments
        Returns:
            The response from the API.

        """
        with BaleSafirAPI(**self.config.model_dump()) as bale:
            bale.authenticate()
            resp = bale.send_otp(phone=to, otp=int(otp))
            resp.raise_for_status()
            return resp.json()


if __name__ == "__main__":
    import os

    import dotenv

    dotenv.load_dotenv()

    bale = BaleSafirAPI(
        client_id=os.getenv("USSO_BALE_CLIENT_ID"),
        client_secret=os.getenv("USSO_BALE_CLIENT_SECRET"),
    )
    bale.authenticate()
    resp = bale.send_otp(phone="989122341769", otp=312875)
