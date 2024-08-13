import asyncio
import json
import logging
from pathlib import Path

import aiohttp
from aiohttp import ClientError, ClientTimeout
from eth_typing import HexStr
from web3 import Web3

from src.config import settings
from src.exits import relayer
from src.exits.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


async def run_tasks():
    share_indexes = get_share_indexes()

    # Cluster lock contains public keys and public key shares
    cluster_lock = load_cluster_lock()

    for share_index in share_indexes:
        node_index = share_index - 1

        pub_key_to_share = {}
        for dv in cluster_lock['distributed_validators']:
            public_key = dv['distributed_public_key']
            public_key_share = dv['public_shares'][node_index]
            pub_key_to_share[public_key] = public_key_share

        keystores_dir = Path(settings.keystores_dir_template.format(node_index=node_index))

        # keystore is a mapping private-key-share -> public-key-share
        keystore = await LocalKeystore.load(keystores_dir)

        logger.info('Starting task for share_index %s', share_index)
        asyncio.create_task(poll_exits_and_push_signatures(pub_key_to_share, keystore, share_index))

    # Keep tasks running
    while True:
        await asyncio.sleep(0.1)


def get_share_indexes():
    return settings.share_indexes or [settings.share_index]


def load_cluster_lock() -> dict:
    return json.load(open(settings.obol_cluster_lock_path, encoding='ascii'))


# pylint: disable=redefined-builtin
async def poll_exits_and_push_signatures(
    pub_key_to_share: dict[HexStr, HexStr], keystore: LocalKeystore, share_index: int
) -> None:
    async with aiohttp.ClientSession(timeout=ClientTimeout(settings.relayer_timeout)) as session:
        while True:
            # get exits from Relayer
            exits = await poll_exits(session)

            # calculate exit signature shares
            public_key_to_exit_signature: dict[HexStr, HexStr] = {}
            for exit in exits:
                public_key = exit['public_key']

                pub_key_share = pub_key_to_share.get(public_key)
                if pub_key_share is None:
                    # Another cluster owns current public key
                    continue

                exit_signature = await keystore.get_exit_signature(
                    exit['validator_index'],
                    pub_key_share,
                    settings.network_config.SHAPELLA_FORK,
                    settings.network_config.GENESIS_VALIDATORS_ROOT,
                )
                public_key_to_exit_signature[public_key] = Web3.to_hex(exit_signature)

            # push exit signature shares to Relayer
            if public_key_to_exit_signature:
                await relayer.push_exit_signatures(
                    session, public_key_to_exit_signature, share_index
                )

            await asyncio.sleep(settings.poll_interval)


async def poll_exits(session):
    while True:
        try:
            if exits := await relayer.get_exits(session):
                return exits
        except (ClientError, asyncio.TimeoutError):
            logger.exception('Failed to poll exits')

        await asyncio.sleep(settings.poll_interval)
