import asyncio
import logging
import time
from typing import cast

from src.common.setup_logging import ExtendedLogger
from src.config import settings

logger = cast(ExtendedLogger, logging.getLogger(__name__))


class BaseTask:
    async def process_block(self) -> None:
        raise NotImplementedError

    async def run(self) -> None:
        while True:
            start_time = time.time()
            try:
                await self.process_block()
            except Exception as exc:
                logger.exception(exc)

            block_processing_time = time.time() - start_time
            sleep_time = max(
                float(settings.network_config.SECONDS_PER_BLOCK) - block_processing_time, 0
            )
            await asyncio.sleep(sleep_time)
