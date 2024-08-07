import logging

from aiohttp import ClientSession
from eth_typing import BLSSignature, HexStr
from web3 import Web3

from src.config import settings

logger = logging.getLogger(__name__)


async def get_exits(session: ClientSession) -> list[dict]:
    res = await session.get(f'{settings.relayer_endpoint}/exits')
    res.raise_for_status()
    jsn = await res.json()
    return jsn['exits']


async def push_signature(
    session: ClientSession,
    public_key: HexStr,
    exit_signature: BLSSignature,
) -> None:
    share_index = settings.share_index
    jsn = {
        'public_key': public_key,
        'share_index': share_index,
        'signature': Web3.to_hex(exit_signature),
    }
    logger.info('push exit signature for share_index %s', share_index)
    res = await session.post(f'{settings.relayer_endpoint}/exit-signature', json=jsn)
    res.raise_for_status()
