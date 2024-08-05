"""Constants for tests."""

from aiovolkswagen.volkswagen import VERSION

VOLKSWAGEN_URL = "https://demo.volkswagen.io"

HEADERS = {
    "User-Agent": f"AioVolkswagen/{VERSION}",
    "Accept": "application/json, text/plain, */*",
}
