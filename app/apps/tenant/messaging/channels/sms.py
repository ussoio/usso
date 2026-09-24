"""SMS (Kavenegar) channel."""

import json
from typing import Literal

import httpx
from pydantic import BaseModel, Field

from .base import AbstractChannel

# Default requests timeout in seconds.
DEFAULT_TIMEOUT = 10


class KavenegarSMSConfig(BaseModel):
    """Kavenegar SMS config."""

    # provider: str = Field(description="The provider name")
    api_key: str = Field(description="The API key")
    # template_key: str | None = None = Field(description="The template key")


class APIError(Exception):
    """API error."""

    pass


class HTTPError(Exception):
    """HTTP error."""

    pass


class KavenegarAPI(httpx.Client):
    """
    Kavenegar API client.

    See: https://kavenegar.com/rest.html.
    """

    version = "v1"
    host = "api.kavenegar.com"

    def __init__(self, *, api_key: str, **kwargs: object) -> None:
        """
        Initialize Kavenegar API client.

        :param str apikey: Kavengera API Key
        :param int timeout: request timeout, default is 10
        :param dict proxies: Dictionary mapping protocol to the URL of the proxy:
            {
                'http': 'http://192.168.1.10:3128',
                'https': 'http://192.168.1.10:3129',
            }
        """
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "charset": "utf-8",
        } | kwargs.get("headers", {})
        super().__init__(headers=headers, **kwargs)
        self.api_key = api_key
        self.api_key_mask = f"{api_key[:2]}********{api_key[-2:]}"

    def __repr__(self) -> str:
        """Return the string representation of the KavenegarAPI."""
        return f"kavenegar.KavenegarAPI({self.api_key_mask!r})"

    def __str__(self) -> str:
        """Return the string representation of the KavenegarAPI."""
        return f"kavenegar.KavenegarAPI({self.api_key_mask!s})"

    def _pars_params_to_json(
        self, params: dict
    ) -> dict[str, str | int | list[str] | None]:
        """
        Format parameters for Kavenegar API.

        Kavenegar api server expects the parameters in a JSON-like array format,
        but the requests library form-encode each key-value pair
        Params (dict):
        { sender: ["30002626", "30002627", "30002727", ], }
        request behavior:
        sender=30002626&sender=30002627&sender=30002727
        Server expectation:
        sender=["30002626","30002627","30002727"].
        """
        # Convert lists to JSON-like strings
        formatted_params: dict[str, str | int | list[str] | None] = {}
        for key, value in params.items():
            if isinstance(value, (dict, list, tuple)):
                formatted_params[key] = json.dumps(value)
            else:
                formatted_params[key] = value
        return formatted_params

    def server_request(
        self,
        action: str,
        method: str,
        params: dict[str, str | int | list[str] | None] | None = None,
    ) -> list[dict[str, str | int | None]]:
        """Send a request to the Kavenegar API."""
        if params is None:
            params = {}
        if isinstance(params, dict):
            params = self._pars_params_to_json(params)
        url = (
            f"https://{self.host}/{self.version}/{self.api_key}/{action}/{method}.json"
        )
        try:
            content = self.post(url, headers=self.headers, data=params).content
            try:
                response = json.loads(content.decode("utf-8"))
                if response["return"]["status"] == 200:
                    return response["entries"]
                else:
                    raise APIError(
                        "APIException[{}] {}".format(
                            response["return"]["status"],
                            response["return"]["message"],
                        )
                    )
            except ValueError as e:
                raise HTTPError(e) from e
        except httpx.HTTPError as e:
            message = str(e).replace(self.api_key, self.api_key_mask)
            raise HTTPError(message) from None

    def sms_send(
        self,
        *,
        receptor: str,
        message: str,
        sender: str | None = None,
        date: int | None = None,
        type: str | None = None,  # ruff:ignore[builtin-argument-shadowing]
        localid: int | None = None,
        hide: int | None = None,
        tag: str | None = None,
    ) -> list[dict[str, str | int | None]]:
        """
        Send an SMS.

        :param receptor: The receptor phone number
        :param message: The message to send
        :param sender: The sender phone number
        :param date: The date to send the SMS
        :param type: The type of the SMS
        :param localid: The local ID of the SMS
        :param hide: The hide of the SMS
        :param tag: The tag of the SMS
        :return: The response from the API
        """
        params: dict[str, str | int | None] = {
            "receptor": receptor,
            "message": message,
        }
        if sender:
            params["sender"] = sender
        if date:
            params["date"] = sender
        if type:
            params["type"] = sender
        if localid:
            params["localid"] = sender
        if hide is not None:
            params["hide"] = hide
        if tag:
            params["tag"] = tag
        return self.server_request("sms", "send", params)

    def sms_sendarray(
        self,
        *,
        receptor: list[str],
        sender: list[str],
        message: list[str],
        date: int | None = None,
        type: list[str] | None = None,  # ruff:ignore[builtin-argument-shadowing]
        localmessageids: list[int] | None = None,
        hide: int | None = None,
        tag: str | None = None,
    ) -> list[dict[str, str | int | None]]:
        """
        Send an SMS array.

        Args:
            receptor: The receptor phone numbers
            sender: The sender phone numbers
            message: The messages to send
            date: The date to send the SMS
            type: The types of the SMS
            localmessageids: The local message IDs
            hide: The hide of the SMS
            tag: The tags of the SMS

        Returns:
            The response from the API

        """
        params: dict[str, str | list[str] | int | None] = {
            "receptor": receptor,
            "message": message,
        }
        if sender:
            params["sender"] = sender
        if date:
            params["date"] = sender
        if type:
            params["type"] = sender
        if localmessageids:
            params["localmessageids"] = sender
        if hide is not None:
            params["hide"] = hide
        if tag:
            params["tag"] = tag
        return self.server_request("sms", "send", params)

    def sms_status(self, *, messageid: int) -> list[dict[str, str | int | None]]:
        """
        Get the status of an SMS.

        Args:
            messageid: The message ID
        Returns:
            The response from the API

        """
        return self.server_request("sms", "status", {"messageid": messageid})

    def sms_status_localmessageid(
        self, *, localid: int
    ) -> list[dict[str, str | int | None]]:
        """
        Get the status of an SMS by local message ID.

        Args:
            localid: The local message ID
        Returns:
            The response from the API

        """
        return self.server_request("sms", "statuslocalmessageid", {"localid": localid})

    def sms_status_receptor(
        self, *, receptor: str, startdate: int, enddate: int | None = None
    ) -> list[dict[str, str | int | None]]:
        """
        Get the status of an SMS by receptor.

        Args:
            receptor: The receptor phone number
            startdate: The start date
            enddate: The end date
        Returns:
            The response from the API

        """
        params = {"receptor": receptor, "startdate": startdate}
        if enddate:
            params["enddata"] = enddate
        return self.server_request("sms", "statuslocalmessageid", params)

    def sms_select(self, *, messageid: int) -> list[dict[str, str | int | None]]:
        """
        Get the status of an SMS by message ID.

        Args:
            messageid: The message ID
        Returns:
            The response from the API

        """
        return self.server_request("sms", "select", {"messageid": messageid})

    def sms_selectoutbox(
        self,
        *,
        startdate: int,
        enddate: int | None = None,
        sender: str | None = None,
    ) -> list[dict[str, str | int | None]]:
        """
        Get the status of an SMS by message ID.

        Args:
            startdate: The start date
            enddate: The end date
            sender: The sender phone number

        Returns:
            The response from the API

        """
        params: dict[str, object] = {"startdate": startdate}
        if enddate:
            params["enddate"] = enddate
        if sender:
            params["sender"] = sender
        return self.server_request("sms", "selectoutbox", params)

    def sms_latestoutbox(
        self, *, pagesize: int | None = None, sender: str | None = None
    ) -> list[dict[str, str | int | None]]:
        """
        Get the latest outbox SMS.

        Args:
            pagesize: The page size
            sender: The sender phone number
        Returns:
            The response from the API

        """
        params = {}
        if pagesize is not None:
            params["pagesize"] = pagesize
        if sender:
            params["sender"] = sender
        return self.server_request("sms", "latestoutbox", params)

    def sms_countoutbox(
        self,
        *,
        startdate: int,
        enddate: int | None = None,
        status: int | None = None,
    ) -> list[dict[str, str | int | None]]:
        """
        Get the count of outbox SMS.

        Args:
            startdate: The start date
            enddate: The end date
            status: The status of the SMS
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {"startdate": startdate}
        if enddate:
            params["enddate"] = enddate
        if status is not None:
            params["status"] = status
        return self.server_request("sms", "countoutbox", params)

    def sms_cancel(self, *, messageid: int) -> list[dict[str, str | int | None]]:
        """
        Cancel an SMS.

        Args:
            messageid: The message ID
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {"messageid": messageid}
        return self.server_request("sms", "cancel", params)

    def sms_receive(
        self, *, linenumber: str, isread: bool | None = None
    ) -> list[dict[str, str | int | None]]:
        """
        Get the SMS received by a phone number.

        Args:
            linenumber: The phone number
            isread: Whether the SMS is read
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {"linenumber": linenumber}
        if isread is not None:
            params["isread"] = int(isread)
        return self.server_request("sms", "receive", params)

    def sms_countinbox(
        self,
        *,
        startdate: int,
        enddate: int | None = None,
        linenumber: str | None = None,
        isread: bool | None = None,
    ) -> dict[str, str | int | None]:
        """
        Get the count of inbox SMS.

        Args:
            startdate: The start date
            enddate: The end date
            linenumber: The phone number
            isread: Whether the SMS is read
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {"startdate": startdate}
        if enddate:
            params["enddate"] = enddate
        if linenumber:
            params["linenumber"] = linenumber
        if isread is not None:
            params["isread"] = int(isread)
        return self.server_request("sms", "countinbox", params)

    def sms_inboxpaged(
        self,
        *,
        linenumber: str,
        isread: bool,
        startdate: int | None = None,
        enddate: int | None = None,
        pagenumber: int | None = None,
    ) -> dict[str, str | int | None]:
        """
        Get the inbox SMS paged.

        Args:
            linenumber: The phone number
            isread: Whether the SMS is read
            startdate: The start date
            enddate: The end date
            pagenumber: The page number
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {
            "linenumber": linenumber,
            "isread": int(isread),
        }
        if startdate:
            params["startdate"] = startdate
        if enddate:
            params["enddate"] = enddate
        if pagenumber is not None:
            params["pagenumber"] = pagenumber
        return self.server_request("sms", "inboxpaged", params)

    def line_blockedlist(
        self,
        *,
        linenumber: str,
        blockreason: Literal[
            0,  # webservice
            1,  # panel
            2,  # laghv 11
            3,  # admin
            10,  # unknown
        ]
        | None = None,
        startdate: int | None = None,
        pagenumber: int | None = None,
    ) -> dict[str, str | int | None]:
        """
        Get the blocked list of a phone number.

        Args:
            linenumber: The phone number
            blockreason: The block reason
            startdate: The start date
            pagenumber: The page number
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {"linenumber": linenumber}
        if blockreason:
            params["blockreason"] = blockreason
        if startdate:
            params["startdate"] = startdate
        if pagenumber is not None:
            params["pagenumber"] = pagenumber
        return self.server_request("line", "blocked/list", params)

    def verify_lookup(
        self,
        *,
        receptor: str,
        token: str,
        token2: str | None = None,
        token3: str | None = None,
        token10: str | None = None,
        token20: str | None = None,
        template: str,
        type: str | None = None,  # ruff:ignore[builtin-argument-shadowing]
        tag: str | None = None,
    ) -> dict[str, str | int | None]:
        """
        Lookup a verification token.

        Args:
            receptor: The phone number
            token: The token
            token2: The token2
            token3: The token3
            token10: The token10
            token20: The token20
            template: The template
            type: The type
            tag: The tag
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {
            "receptor": receptor,
            "token": token,
            "template": template,
        }
        if token2:
            params["token2"] = token2
        if token3:
            params["token3"] = token3
        if token10:
            params["token10"] = token10
        if token20:
            params["token20"] = token20
        if type:
            params["type"] = type
        if tag:
            params["tag"] = tag

        return self.server_request("verify", "lookup", params)

    def call_maketts(
        self,
        *,
        receptor: str,
        message: str,
        date: int | None = None,
        localid: str | None = None,
        # repeat: Literal[0, 1, 2, 3, 4, 5] | None = None,
        tag: str | None = None,
    ) -> dict[str, str | int | None]:
        """
        Make a call.

        Args:
            receptor: The phone number
            message: The message
            date: The date
            localid: The local ID
            tag: The tag
        Returns:
            The response from the API

        """
        params: dict[str, str | int | None] = {
            "receptor": receptor,
            "message": message,
        }
        if date:
            params["date"] = date
        if localid:
            params["localid"] = localid
        # if repeat:
        #     params["repeat"] = repeat
        if tag:
            params["tag"] = tag
        return self.server_request("call", "maketts", params)

    def call_status(
        self, params: dict[str, str | int | None] | None = None
    ) -> dict[str, str | int | None]:
        """
        Get the status of a call.

        Args:
            params: The parameters
        Returns:
            The response from the API

        """
        return self.server_request("call", "status", params)

    def account_info(self) -> dict[str, str | int | None]:
        """
        Get the account information.

        Returns:
            The response from the API

        """
        return self.server_request("account", "info")

    def account_config(
        self,
        *,
        apilogs: str | None = None,
        dailyreport: str | None = None,
        debugmode: str | None = None,
        defaultsender: str | None = None,
        mincreditalarm: int | None = None,
        resendfailed: str | None = None,
    ) -> dict[str, str | int | None]:
        """
        Get the account configuration.

        Args:
            apilogs: The API logs
            dailyreport: The daily report
            debugmode: The debug mode
            defaultsender: The default sender
            mincreditalarm: The minimum credit alarm
            resendfailed: The resend failed

        Returns:
            The response from the API

        """
        return self.server_request("account", "config")


class KavenegarSMSChannel(AbstractChannel):
    """Kavenegar SMS channel."""

    channel_type = "sms"
    supports_phone = True
    ConfigType = KavenegarSMSConfig

    def send(self, *, to: str, message: str, **kwargs: object) -> None:
        """
        Send an SMS.

        Args:
            to: The phone number
            message: The message
            **kwargs: Additional arguments

        Returns:
            The response from the API.

        """
        with KavenegarAPI(api_key=self.config.api_key) as client:
            template = kwargs.get("template") or kwargs.get("remote_template_id")
            token = kwargs.get("token") or kwargs.get("otp")
            if template and token is not None:
                client.verify_lookup(
                    receptor=to,
                    token=str(token),
                    token2=kwargs.get("token2"),
                    token3=kwargs.get("token3"),
                    token10=kwargs.get("token10"),
                    token20=kwargs.get("token20"),
                    template=str(template),
                    type=kwargs.get("type"),
                    tag=kwargs.get("tag"),
                )
                return
            client.sms_send(receptor=to, message=message)


if __name__ == "__main__":
    import os

    import dotenv

    dotenv.load_dotenv()
    kavenegar = KavenegarAPI(api_key=os.getenv("KAVENEGAR_API_KEY", ""))
    params = {
        "sender": "100088008088",
        "receptor": "09122341769",
        "message": "وب سرویس پیام کوتاه کاوه نگار",
    }
    response = kavenegar.sms_send(**params)
