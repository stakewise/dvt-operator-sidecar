import aiohttp
from aiohttp import ClientTimeout
from sw_utils.common import urljoin

from src.config import settings
from src.config.settings import ssv_api_base_url, ssv_api_timeout


async def get_operator(operator_id: int) -> dict:
    url = urljoin(ssv_api_base_url, f'/{settings.network}/operators/{operator_id}')
    async with aiohttp.ClientSession(timeout=ClientTimeout(ssv_api_timeout)) as session:
        async with session.get(url) as res:
            res.raise_for_status()
            return await res.json()
