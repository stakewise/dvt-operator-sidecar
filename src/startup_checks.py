import logging
from typing import cast

import aiohttp
from aiohttp import ClientTimeout

from src.common.setup_logging import ExtendedLogger
from src.config import settings
from src.validators import relayer

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def startup_checks() -> bool:
    try:
        await _check_relayer_endpoint()
    except Exception as e:
        logger.error_verbose(
            'Relayer endpoint check failed for %s: %s', settings.relayer_endpoint, e
        )
        return False

    return True


async def _check_relayer_endpoint() -> None:
    async with aiohttp.ClientSession(timeout=ClientTimeout(settings.relayer_timeout)) as session:
        await relayer.get_exits(session)
