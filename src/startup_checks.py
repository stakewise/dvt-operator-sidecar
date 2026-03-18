import asyncio
import logging
from typing import cast

import aiohttp
from aiohttp import ClientTimeout

from src.common.setup_logging import ExtendedLogger
from src.config import settings
from src.validators import relayer

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def startup_checks() -> None:
    info = await _wait_for_relayer_endpoint()
    _check_relayer_network(info)


async def _wait_for_relayer_endpoint() -> dict:
    logger.info('Waiting for relayer endpoint %s', settings.relayer_endpoint)
    while True:
        try:
            async with aiohttp.ClientSession(
                timeout=ClientTimeout(settings.relayer_timeout)
            ) as session:
                info = await relayer.get_info(session)
            logger.info('Relayer endpoint is available')
            return info
        except Exception as e:
            logger.error_verbose(
                'Relayer endpoint check failed for %s: %s', settings.relayer_endpoint, e
            )
        await asyncio.sleep(settings.poll_interval)


def _check_relayer_network(info: dict) -> None:
    relayer_network = info['network']
    if relayer_network != settings.network:
        raise ValueError(
            f'Relayer network "{relayer_network}" does not match '
            f'Sidecar network "{settings.network}"'
        )
