"""Asynchronous Python client for Volkswagen."""

from typing import AsyncGenerator, Generator

import aiohttp
from aioresponses import aioresponses
import pytest

from aiovolkswagen import Volkswagen
from syrupy import SnapshotAssertion

from .syrupy import VolkswagenSnapshotExtension


@pytest.fixture(name="snapshot")
def snapshot_assertion(snapshot: SnapshotAssertion) -> SnapshotAssertion:
    """Return snapshot assertion fixture with the Volkswagen extension."""
    return snapshot.use_extension(VolkswagenSnapshotExtension)


@pytest.fixture(name="volkswagen_client")
async def client() -> AsyncGenerator[Volkswagen, None]:
    """Return a Volkswagen client."""
    async with aiohttp.ClientSession() as session, Volkswagen(
        session=session,
    ) as volkswagen_client:
        yield volkswagen_client


@pytest.fixture(name="responses")
def aioresponses_fixture() -> Generator[aioresponses, None, None]:
    """Return aioresponses fixture."""
    with aioresponses() as mocked_responses:
        yield mocked_responses
