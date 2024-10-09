import asyncio
import logging
from pathlib import Path
from typing import cast

import aiohttp
from aiohttp import ClientError, ClientTimeout
from eth_typing import HexStr
from web3 import Web3

from src.common.setup_logging import ExtendedLogger
from src.config import settings
from src.config.settings import OBOL, SSV
from src.validators import relayer
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.load import load_keystore
from src.validators.keystores.obol import ObolKeystore
from src.validators.keystores.ssv import SSVKeystore

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def run_tasks() -> None:
    if settings.cluster_type == OBOL:
        try:
            await obol_create_tasks()
        except Exception as e:
            logger.exception_verbose(e)
            return

    if settings.cluster_type == SSV:
        try:
            await ssv_create_tasks()
        except Exception as e:
            logger.exception_verbose(e)
            return

    logger.info('All tasks started')

    # Keep tasks running
    while True:
        await asyncio.sleep(0.1)


async def obol_create_tasks() -> None:
    obol_node_indexes = get_obol_node_indexes()

    # keystore is a mapping private-key-share -> public-key-share
    # Testing setup: multiple keystores
    # Production setup: single keystore
    keystore: BaseKeystore | None = None
    if not settings.obol_keystores_dir_template:
        keystore = await load_keystore()

    for node_index in obol_node_indexes:
        if settings.obol_keystores_dir_template:
            obol_keystores_dir = Path(
                settings.obol_keystores_dir_template.format(node_index=node_index)
            )
            keystore = await ObolKeystore.load_from_dir(obol_keystores_dir, node_index)

        logger.info('Starting task for node index %s', node_index)

        share_index = node_index + 1
        asyncio.create_task(
            poll_exits_and_push_signatures(cast(BaseKeystore, keystore), share_index)
        )


async def ssv_create_tasks() -> None:
    ssv_operator_ids = get_ssv_operator_ids()

    # keystore is a mapping private-key-share -> public-key-share
    # Testing setup: multiple keystores
    # Production setup: single keystore
    keystore: BaseKeystore | None = None
    if not settings.ssv_operator_key_file_template:
        keystore = await load_keystore()

    for ssv_operator_id in ssv_operator_ids:
        if settings.ssv_operator_key_file_template:
            ssv_operator_key_file = settings.ssv_operator_key_file_template.format(
                operator_id=ssv_operator_id
            )
            ssv_operator_password_file = settings.ssv_operator_password_file_template.format(
                operator_id=ssv_operator_id
            )
            keystore = SSVKeystore.load_as_operator(
                ssv_operator_id, ssv_operator_key_file, ssv_operator_password_file
            )

        logger.info('Starting task for operator id %s', ssv_operator_id)
        asyncio.create_task(
            poll_exits_and_push_signatures(cast(BaseKeystore, keystore), ssv_operator_id)
        )


def get_obol_node_indexes() -> list[int]:
    if settings.obol_node_indexes:
        return settings.obol_node_indexes

    if settings.obol_node_index is not None:
        return [settings.obol_node_index]

    raise RuntimeError('OBOL_NODE_INDEXES or OBOL_NODE_INDEX must be set')


def get_ssv_operator_ids() -> list[int]:
    if settings.ssv_operator_ids:
        return settings.ssv_operator_ids

    if settings.ssv_operator_id is not None:
        return [settings.ssv_operator_id]

    raise RuntimeError('SSV_OPERATOR_IDS or SSV_OPERATOR_ID must be set')


# pylint: disable=redefined-builtin
async def poll_exits_and_push_signatures(keystore: BaseKeystore, share_index: int) -> None:
    async with aiohttp.ClientSession(timeout=ClientTimeout(settings.relayer_timeout)) as session:
        while True:
            # get validators from Relayer
            exits = await poll_exits(session)

            # calculate exit signature shares
            public_key_to_exit_signature: dict[HexStr, HexStr] = {}
            for exit in exits:
                public_key = exit['public_key']

                pub_key_share = keystore.pubkey_to_share.get(public_key)
                if pub_key_share is None:
                    # Another cluster owns current public key
                    continue

                if exit['is_exit_signature_ready']:
                    continue

                exit_signature = await keystore.get_exit_signature(
                    exit['validator_index'],
                    pub_key_share,
                    settings.network_config.SHAPELLA_FORK,
                )
                public_key_to_exit_signature[public_key] = Web3.to_hex(exit_signature)

            # push exit signature shares to Relayer
            if public_key_to_exit_signature:
                await relayer.push_exit_signatures(
                    session, public_key_to_exit_signature, share_index
                )

            await asyncio.sleep(settings.poll_interval)


async def poll_exits(session: aiohttp.ClientSession) -> list[dict]:
    """
    Periodically checks relayer for new validator exits.
    """
    while True:
        try:
            if exits := await relayer.get_exits(session):
                return exits
        except (ClientError, asyncio.TimeoutError) as e:
            logger.error_verbose('Failed to poll validators: %s', e)

        await asyncio.sleep(settings.poll_interval)
