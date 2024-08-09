"""Example usage of the aiovolkswagen library to login to the Volkswagen We Connect portal."""

import asyncio

from aiovolkswagen import Volkswagen


async def main() -> None:
    """Main function."""
    vw_client = Volkswagen()
    await vw_client.login("username", "password")


if __name__ == "__main__":
    asyncio.run(main())
