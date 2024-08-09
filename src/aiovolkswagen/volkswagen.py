"""Asynchronous Python client for Volkswagen."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Self
from urllib.parse import parse_qs

from aiohttp import ClientSession
from aiohttp.hdrs import METH_GET

from aiovolkswagen.exceptions import VolkswagenConnectionError, VolkswagenError
from aiovolkswagen.models import OpenIDConfiguration, Tokens
from aiovolkswagen.const import HEADERS_AUTH, APP_URI, CLIENT_ID
from aiovolkswagen.exceptions import (
    VolkswagenAuthenticationError,
    VolkswagenAccountLockedError,
    VolkswagenEULAError,
)
from aiovolkswagen.util import get_random_string
from aiovolkswagen.auth.login import (
    EmailFormParser,
    ClassicPasswordFormParser,
    DynamicPasswordFormParser,
)

from yarl import URL

VERSION = metadata.version(__package__)

LOGGER = logging.getLogger(__package__)


@dataclass
class Volkswagen:
    """Main class for handling connections with Volkswagen."""

    session: ClientSession | None = None
    request_timeout: int = 10
    _close_session: bool = False
    _session_auth_headers: dict[str, Any] = field(default_factory=HEADERS_AUTH.copy)

    async def _request(
        self,
        url: str | URL,
        *,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> str:
        """Handle a request to Volkswagen."""
        headers = {
            "User-Agent": f"AioVolkswagen/{VERSION}",
            "Accept": "application/json",
        }
        self.__ensure_session()
        assert self.session

        kwargs = {
            "headers": headers,
            "params": params,
            "json": data,
            **kwargs,
        }

        try:
            async with asyncio.timeout(self.request_timeout):
                response = await self.session.request(METH_GET, url, **kwargs)
        except asyncio.TimeoutError as exception:
            msg = "Timeout occurred while connecting to Volkswagen"
            raise VolkswagenConnectionError(msg) from exception

        if response.status != 200:
            text = await response.text()
            msg = "Cannot connect to Volkswagen"
            raise VolkswagenConnectionError(
                msg,
                {"response": text},
            )

        content_type = response.headers.get("Content-Type", "")

        if "application/json" not in content_type:
            text = await response.text()
            msg = "Unexpected response from Volkswagen"
            raise VolkswagenError(
                msg,
                {"Content-Type": content_type, "response": text},
            )

        return await response.text()

    def __ensure_session(self) -> None:
        if self.session is None:
            self.session = ClientSession()
            self._close_session = True

    async def get_openid_configuration(self) -> OpenIDConfiguration:
        """Get the OpenID configuration."""
        response = await self._request(
            "https://identity.vwgroup.io/.well-known/openid-configuration"
        )
        return OpenIDConfiguration.from_json(response)

    async def login(self, username: str, password: str) -> Tokens:  # pylint: disable=too-many-branches,too-many-statements
        """Login to Volkswagen."""
        openid_configuration = await self.get_openid_configuration()
        url = URL(openid_configuration.authorization_endpoint).with_query(
            {
                "redirect_uri": "cupraconnect://identity-kit/login",
                "nonce": get_random_string(),
                "state": get_random_string(),
                "response_type": "code id_token token",
                "client_id": CLIENT_ID,
                "scope": "openid profile address phone email birthdate nationalIdentifier cars mbb dealers badge nationality",
            }
        )
        self.__ensure_session()
        assert self.session
        request = await self.session.get(
            url, headers=self._session_auth_headers, allow_redirects=False
        )
        if "Location" not in request.headers:
            raise VolkswagenAuthenticationError("Missing `location` header")
        location = request.headers["Location"]
        if "error" in location:
            location_url = URL(location)
            error = location_url.query.get("error", "")
            if "error_description" in location:
                error = location_url.query["error_description"]
            raise VolkswagenAuthenticationError(error)

        if "signin-service" in location:
            location = await self._sign_in_to_service(
                location, openid_configuration, username, password
            )

        max_depth = 10
        while not location.startswith(APP_URI):
            if "error" in location:
                location_url = URL(location)
                error = location_url.query["error"]
                if error == "login.error.throttled":
                    timeout = location_url.query["enableNextButtonAfterSeconds"]
                    raise VolkswagenAccountLockedError(
                        f"Account locked for {timeout} seconds"
                    )
                if error == "login.errors.password_invalid":
                    raise VolkswagenAuthenticationError("Invalid password")
                raise VolkswagenAuthenticationError(error)
            if "terms-and-conditions" in location:
                raise VolkswagenEULAError("Accept terms and conditions")
            LOGGER.debug("Following redirect to %s", location)
            request = await self.session.get(
                location, headers=self._session_auth_headers, allow_redirects=False
            )
            if "Location" not in request.headers:
                raise VolkswagenAuthenticationError("Missing `location` header")
            location = request.headers["Location"]
            max_depth -= 1
            if max_depth == 0:
                raise VolkswagenAuthenticationError("Max redirect depth reached")
        LOGGER.debug(location)
        location_url = URL(location)
        code = parse_qs(location_url.fragment)["code"][0]
        id_token = parse_qs(location_url.fragment)["id_token"][0]
        try:
            request = await self.session.post(
                "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode",
                headers=HEADERS_AUTH,
                data={"auth_code": code, "id_token": id_token, "brand": "cupra"},
            )
            request.raise_for_status()
        except Exception as e:
            raise VolkswagenAuthenticationError("Invalid request") from e
        return Tokens.from_json(await request.text())

    async def _sign_in_to_service(
        self,
        location: str,
        openid_config: OpenIDConfiguration,
        username: str,
        password: str,
    ) -> str:
        """Sign in to the service."""
        assert self.session
        response = await self.session.get(
            location, headers=self._session_auth_headers, allow_redirects=False
        )
        html = await response.text()
        parser = EmailFormParser()
        parser.feed(html)
        if not parser.action:
            raise VolkswagenAuthenticationError("No action found in form")
        self._session_auth_headers["Referer"] = openid_config.authorization_endpoint
        self._session_auth_headers["Origin"] = openid_config.issuer
        form_data = {**parser.form_data, "email": username}
        response = await self.session.post(
            f"{openid_config.issuer}{parser.action}",
            headers=self._session_auth_headers,
            data=form_data,
        )
        if response.status != 200:
            raise VolkswagenAuthenticationError("Invalid request")
        html = await response.text()
        post_action: str
        if "credentialsForm" in html:
            password_parser = ClassicPasswordFormParser()
            password_parser.feed(html)
            if not password_parser.action:
                raise VolkswagenAuthenticationError("No action found in form")
            data = {**password_parser.form_data, "password": password}
            post_action = password_parser.action
        elif "templateModel" in html:
            dynamic_password_parser = DynamicPasswordFormParser()
            dynamic_password_parser.feed(html)
            assert dynamic_password_parser.action
            data = {
                **form_data,
                **dynamic_password_parser.form_data,
                "password": password,
            }
            post_action = dynamic_password_parser.action
        else:
            raise VolkswagenAuthenticationError("No password form found")
        url = f"{openid_config.issuer}{post_action}"
        if "signin-service" not in url or CLIENT_ID not in url:
            url = f"{openid_config.issuer}/signin-service/v1/{CLIENT_ID}/{post_action}"
        self._session_auth_headers["Referer"] = f"{openid_config.issuer}{parser.action}"
        LOGGER.debug(url)
        LOGGER.debug(self._session_auth_headers)
        LOGGER.debug(data)
        response = await self.session.post(
            url, headers=self._session_auth_headers, data=data, allow_redirects=False
        )
        if (redirect_location := response.headers.get("Location")) is None:
            raise VolkswagenAuthenticationError("Missing `location` header")
        LOGGER.debug(redirect_location)
        return redirect_location

    async def close(self) -> None:
        """Close open client session."""
        if self.session and self._close_session:
            await self.session.close()

    async def __aenter__(self) -> Self:
        """Async enter.

        Returns
        -------
            The Volkswagen object.
        """
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Async exit.

        Args:
        ----
            _exc_info: Exec type.
        """
        await self.close()
