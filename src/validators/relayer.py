import logging
from typing import cast

from aiohttp import ClientSession
from eth_typing import HexStr
from sw_utils.common import urljoin

from src.common.setup_logging import ExtendedLogger
from src.config import settings

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def get_info(session: ClientSession) -> dict:
    url = urljoin(settings.relayer_endpoint, '/info')
    async with session.get(url) as res:
        res.raise_for_status()
        jsn = await res.json()
    return jsn


async def get_exits(session: ClientSession) -> list[dict]:
    """
    `exits` represent exit messages to sign.
    """
    url = urljoin(settings.relayer_endpoint, '/exits')
    async with session.get(url) as res:
        res.raise_for_status()
        jsn = await res.json()
    return jsn['exits']


async def push_exit_signatures(
    session: ClientSession,
    public_key_to_exit_signature: dict[HexStr, HexStr],
    share_index: int,
) -> None:
    shares = []
    for public_key, exit_signature in public_key_to_exit_signature.items():
        shares.append(
            {
                'public_key': public_key,
                'exit_signature': exit_signature,
            }
        )
    jsn = {'share_index': share_index, 'shares': shares}
    logger.info('push exit signatures for share_index %s', share_index)
    url = urljoin(settings.relayer_endpoint, '/exit-signature')
    async with session.post(url, json=jsn) as res:
        res.raise_for_status()
