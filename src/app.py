import asyncio
import logging
from typing import cast

from src.common.database import db_client
from src.common.setup_logging import ExtendedLogger, setup_logging, setup_sentry
from src.common.utils import get_project_version
from src.config.settings import validate_settings
from src.setup_database import setup_database

setup_logging()
setup_sentry()

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def app() -> None:
    # Delay application imports because they must go after `setup_logging`.
    # pylint: disable=import-outside-toplevel
    from src.startup_checks import startup_checks
    from src.validators.tasks import create_tasks

    validate_settings()

    version = get_project_version()
    logger.info('Starting DVT Sidecar service %s', version)

    await setup_database()

    is_checks_ok = await startup_checks()
    if not is_checks_ok:
        return

    try:
        await create_tasks()
        logger.info('DVT Sidecar service started')

        # Keep tasks running
        while True:
            await asyncio.sleep(0.1)
    except Exception as e:
        logger.exception_verbose(e)
    finally:
        # prevent hanging on shutdown
        await db_client.close()


if __name__ == '__main__':
    asyncio.run(app())
