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


async def get_validators(session: ClientSession) -> list[dict]:
    """
    Get validators from relayer to sign deposit and exit messages.
    """
    url = urljoin(settings.relayer_endpoint, '/validators')
    async with session.get(url) as res:
        res.raise_for_status()
        jsn = await res.json()
    return jsn['validators']


async def push_signatures(
    session: ClientSession,
    public_key_to_signatures: dict[HexStr, tuple[HexStr, HexStr]],
    share_index: int,
) -> None:
    shares = []
    for public_key, (exit_signature, deposit_signature) in public_key_to_signatures.items():
        shares.append(
            {
                'public_key': public_key,
                'exit_signature': exit_signature,
                'deposit_signature': deposit_signature,
            }
        )
    jsn = {'share_index': share_index, 'shares': shares}
    logger.info('push signatures for share_index %s', share_index)
    url = urljoin(settings.relayer_endpoint, '/signatures')
    async with session.post(url, json=jsn) as res:
        res.raise_for_status()
