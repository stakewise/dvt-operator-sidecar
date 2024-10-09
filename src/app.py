import asyncio

from src.common.setup_logging import setup_logging, setup_sentry

setup_logging()
setup_sentry()


if __name__ == '__main__':
    # Delay application imports because they should go after `setup_logging`.
    from src.validators.tasks import run_tasks

    asyncio.run(run_tasks())
