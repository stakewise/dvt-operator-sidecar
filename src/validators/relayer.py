import logging
from urllib.parse import urljoin

from aiohttp import ClientSession
from eth_typing import HexStr

from src.config import settings

logger = logging.getLogger(__name__)


async def get_exits(session: ClientSession) -> list[dict]:
    """
    `exits` represent exit messages to sign.
    """
    url = urljoin(settings.relayer_endpoint, '/exits')
    res = await session.get(url)
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
    res = await session.post(url, json=jsn)
    res.raise_for_status()
