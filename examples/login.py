"""Example usage of the aiovolkswagen library to login to the Volkswagen We Connect portal."""

import asyncio
import logging

from aiovolkswagen import Volkswagen


async def main() -> None:
    """Main function."""
    logging.basicConfig(level=logging.DEBUG)
    async with Volkswagen() as vw_client:
        await vw_client.login("test", "test")


if __name__ == "__main__":
    asyncio.run(main())
