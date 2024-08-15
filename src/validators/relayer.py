import logging

from aiohttp import ClientSession
from eth_typing import HexStr

from src.config import settings

logger = logging.getLogger(__name__)


async def get_exits(session: ClientSession) -> list[dict]:
    res = await session.get(f'{settings.relayer_endpoint}/validators')
    res.raise_for_status()
    jsn = await res.json()
    return jsn['validators']


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
    logger.info('push exit signature for share_index %s', share_index)
    res = await session.post(f'{settings.relayer_endpoint}/exit-signature', json=jsn)
    res.raise_for_status()
