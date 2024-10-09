import asyncio
import logging
from typing import cast

from src.common.setup_logging import ExtendedLogger, setup_logging, setup_sentry

setup_logging()
setup_sentry()

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def app() -> None:
    # Delay application imports because they must go after `setup_logging`.
    # pylint: disable=import-outside-toplevel
    from src.startup_checks import startup_checks
    from src.validators.tasks import create_tasks

    is_checks_ok = await startup_checks()
    if not is_checks_ok:
        return

    await create_tasks()

    logger.info('DVT Sidecar service started')

    # Keep tasks running
    while True:
        await asyncio.sleep(0.1)


if __name__ == '__main__':
    asyncio.run(app())
