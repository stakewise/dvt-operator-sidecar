import aiohttp
from aiohttp import ClientTimeout

from src.config import settings

base_url = 'https://api.ssv.network/api/v4'
timeout = 10


async def get_operator(operator_id: int) -> dict:
    url = f'{base_url}/{settings.network}/operators/{operator_id}'
    async with aiohttp.ClientSession(timeout=ClientTimeout(timeout)) as session:
        async with session.get(url) as res:
            res.raise_for_status()
            return await res.json()
