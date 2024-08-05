"""Asynchronous Python client for Volkswagen."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Self

from aiohttp import ClientSession
from aiohttp.hdrs import METH_GET

from aiovolkswagen.exceptions import VolkswagenConnectionError, VolkswagenError
from aiovolkswagen.models import OpenIDConfiguration

VERSION = metadata.version(__package__)


@dataclass
class Volkswagen:
    """Main class for handling connections with Volkswagen."""

    session: ClientSession | None = None
    request_timeout: int = 10
    _close_session: bool = False

    async def _request(
        self,
        url: str,
        *,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> str:
        """Handle a request to Volkswagen."""
        headers = {
            "User-Agent": f"AioVolkswagen/{VERSION}",
            "Accept": "application/json",
        }

        if self.session is None:
            self.session = ClientSession()
            self._close_session = True

        kwargs = {
            "headers": headers,
            "params": params,
            "json": data,
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

    async def get_openid_configuration(self) -> OpenIDConfiguration:
        """Get the OpenID configuration."""
        response = await self._request(
            "https://identity.vwgroup.io/.well-known/openid-configuration"
        )
        return OpenIDConfiguration.from_json(response)

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
