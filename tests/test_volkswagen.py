"""Asynchronous Python client for Volkswagen."""

from __future__ import annotations

import asyncio
from datetime import date
from typing import TYPE_CHECKING, Any

import aiohttp
from aiohttp.hdrs import METH_GET, METH_POST, METH_PUT, METH_DELETE
from aioresponses import CallbackResult, aioresponses
import pytest
from yarl import URL

from aiovolkswagen.volkswagen import Volkswagen

from aiovolkswagen.exceptions import VolkswagenError, VolkswagenConnectionError
from tests import load_fixture

from .const import HEADERS

if TYPE_CHECKING:
    from syrupy import SnapshotAssertion


async def test_putting_in_own_session(
    responses: aioresponses,
) -> None:
    """Test putting in own session."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    async with aiohttp.ClientSession() as session:
        vw = Volkswagen(session=session)
        await vw.get_openid_configuration()
        assert vw.session is not None
        assert not vw.session.closed
        await vw.close()
        assert not vw.session.closed


async def test_creating_own_session(
    responses: aioresponses,
) -> None:
    """Test creating own session."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    vw = Volkswagen()
    await vw.get_openid_configuration()
    assert vw.session is not None
    assert not vw.session.closed
    await vw.close()
    assert vw.session.closed


async def test_unexpected_server_response(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
) -> None:
    """Test handling unexpected response."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=400,
        headers={"Content-Type": "plain/text"},
        body="Yes",
    )
    with pytest.raises(VolkswagenError):
        assert await volkswagen_client.get_openid_configuration()



async def test_timeout(
    responses: aioresponses,
) -> None:
    """Test request timeout."""

    # Faking a timeout by sleeping
    async def response_handler(_: str, **_kwargs: Any) -> CallbackResult:
        """Response handler for this test."""
        await asyncio.sleep(2)
        return CallbackResult(body="Goodmorning!")

    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        callback=response_handler,
    )
    async with Volkswagen(
        request_timeout=1
    ) as volkswagen_client:
        with pytest.raises(VolkswagenConnectionError):
            assert await volkswagen_client.get_openid_configuration()


async def test_about(
    responses: aioresponses,
    volkswagen_client: Volkswagen,
    snapshot: SnapshotAssertion,
) -> None:
    """Test retrieving openid configuration."""
    responses.get(
        "https://identity.vwgroup.io/.well-known/openid-configuration",
        status=200,
        body=load_fixture("openid-configuration.json"),
    )
    assert await volkswagen_client.get_openid_configuration() == snapshot

