import logging
from typing import cast

import aiohttp
from aiohttp import ClientTimeout

from src.common.setup_logging import ExtendedLogger
from src.config import settings
from src.validators import relayer

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def startup_checks() -> bool:
    """
    :return: True if all checks are ok, False otherwise
    """
    logger.info('Checking relayer endpoint %s', settings.relayer_endpoint)
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
        info = await relayer.get_info(session)

    relayer_network = info['network']
    if relayer_network != settings.network:
        raise ValueError(
            f'Relayer network "{relayer_network}" does not match '
            f'Sidecar network "{settings.network}"'
        )
