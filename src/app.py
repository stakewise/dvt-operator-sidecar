import asyncio

from src.common.setup_logging import setup_logging, setup_sentry
from src.exits.tasks import run_tasks

setup_logging()
setup_sentry()


if __name__ == '__main__':
    asyncio.run(run_tasks())
