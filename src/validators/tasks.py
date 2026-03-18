import asyncio
import logging
from pathlib import Path
from typing import cast

import aiohttp
from aiohttp import ClientError, ClientTimeout
from eth_typing import BlockNumber, HexStr
from sw_utils import get_chain_finalized_head
from web3 import Web3

from src.checkpoints.database import CheckpointCrud, CheckpointType
from src.common.clients import consensus_client, execution_client
from src.common.contracts import ssv_registry_contract
from src.common.database import TransactionConnection
from src.common.setup_logging import ExtendedLogger
from src.common.tasks import BaseTask
from src.config import settings
from src.config.settings import OBOL, SSV
from src.ssv_operators.database import SSVValidatorCrud
from src.ssv_operators.typings import SSVValidator
from src.validators import relayer
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.load import load_keystore
from src.validators.keystores.obol import ObolKeystore
from src.validators.keystores.ssv import SSVKeystore
from src.validators.typings import RelayerValidator

logger = cast(ExtendedLogger, logging.getLogger(__name__))


async def create_tasks() -> None:
    if settings.cluster_type == OBOL:
        await obol_create_tasks()

    if settings.cluster_type == SSV:
        await ssv_create_tasks()


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

        logger.info('Starting signatures task for node index %s', node_index)

        share_index = node_index + 1
        asyncio.create_task(
            poll_validators_and_push_signatures(cast(BaseKeystore, keystore), share_index)
        )


async def ssv_create_tasks() -> None:
    logger.info('Loading SSV keystores')
    keystores_map = cast(dict[int, SSVKeystore], await get_keystores_map())

    logger.info('Starting initial sync of SSV validators')
    await SSVValidatorTask(keystores_map=keystores_map).process_block()

    logger.info('Starting SSV validator sync task')
    asyncio.create_task(SSVValidatorTask(keystores_map=keystores_map).run())

    for ssv_operator_id, keystore in keystores_map.items():
        logger.info('Starting signatures task for operator %s', ssv_operator_id)

        asyncio.create_task(poll_validators_and_push_signatures(keystore, ssv_operator_id))


async def get_keystores_map() -> dict[int, BaseKeystore]:
    """
    Returns a mapping of SSV operator IDs to their keystores.
    Keystore is a mapping from private-key-share to public-key-share.
    Testing setup: multiple keystores.
    Production setup: single keystore.
    """

    keystores_map: dict[int, BaseKeystore] = {}

    if settings.ssv_operator_id:
        keystore = await load_keystore()
        return {settings.ssv_operator_id: keystore}

    for ssv_operator_id in settings.ssv_operator_ids:
        ssv_operator_key_file = settings.ssv_operator_key_file_template.format(
            operator_id=ssv_operator_id
        )
        ssv_operator_password_file = settings.ssv_operator_password_file_template.format(
            operator_id=ssv_operator_id
        )
        keystore = await SSVKeystore.load_as_operator(
            ssv_operator_id, ssv_operator_key_file, ssv_operator_password_file
        )
        keystores_map[ssv_operator_id] = keystore

    return keystores_map


def get_obol_node_indexes() -> list[int]:
    if settings.obol_node_indexes:
        return settings.obol_node_indexes

    if settings.obol_node_index is not None:
        return [settings.obol_node_index]

    raise RuntimeError('OBOL_NODE_INDEXES or OBOL_NODE_INDEX must be set')


async def poll_validators_and_push_signatures(keystore: BaseKeystore, share_index: int) -> None:
    async with aiohttp.ClientSession(timeout=ClientTimeout(settings.relayer_timeout)) as session:
        while True:
            # get validators from Relayer
            validators = await poll_validators(session)

            # calculate exit and deposit signature shares
            public_key_to_signatures: dict[HexStr, tuple[HexStr, HexStr]] = {}
            for validator in validators:
                pub_key_share = keystore.pubkey_to_share.get(validator.public_key)
                if pub_key_share is None:
                    # Another cluster owns current public key
                    continue

                if share_index in validator.share_indexes_ready:
                    continue

                exit_signature = await keystore.get_exit_signature(
                    validator.validator_index,
                    pub_key_share,
                    settings.network_config.SHAPELLA_FORK,
                )
                deposit_signature = await keystore.get_deposit_signature(
                    pub_key_share,
                    validator.vault,
                    validator.amount,
                    validator.validator_type,
                )
                public_key_to_signatures[validator.public_key] = (
                    Web3.to_hex(exit_signature),
                    Web3.to_hex(deposit_signature),
                )

            # push signature shares to Relayer
            if public_key_to_signatures:
                try:
                    await relayer.push_signatures(session, public_key_to_signatures, share_index)
                except (ClientError, asyncio.TimeoutError) as e:
                    logger.error_verbose('Failed to push signatures: %s', e)

            await asyncio.sleep(settings.poll_interval)


async def poll_validators(session: aiohttp.ClientSession) -> list[RelayerValidator]:
    """
    Periodically checks relayer for validators to sign.
    """
    while True:
        try:
            raw_validators = await relayer.get_validators(session)
            logger.info('Got %d validators from relayer', len(raw_validators))
            if raw_validators:
                validators = []
                for raw_validator in raw_validators:
                    try:
                        validators.append(RelayerValidator(**raw_validator))
                    except Exception as e:
                        logger.error_verbose('Failed to parse validator data: %s', e)
                return validators
        except (ClientError, asyncio.TimeoutError) as e:
            logger.error_verbose('Failed to get validators: %s', e)

        await asyncio.sleep(settings.poll_interval)


class SSVValidatorTask(BaseTask):
    """
    Task to scan SSV validators from onchain events.
    """

    def __init__(self, keystores_map: dict[int, SSVKeystore]) -> None:
        self.keystores_map = keystores_map

    @property
    def ssv_operator_ids(self) -> list[int]:
        return list(self.keystores_map.keys())

    async def process_block(self) -> None:
        chain_head = await get_chain_finalized_head(
            consensus_client=consensus_client,
            slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH,
        )
        to_block = chain_head.block_number

        from_block = await self._get_from_block()

        if from_block > to_block:
            return

        # Fetch events
        events = await ssv_registry_contract.get_validator_added_events(
            from_block=from_block, to_block=to_block
        )
        ssv_validators: list[SSVValidator] = []
        ssv_operator_ids_set = set(self.ssv_operator_ids)

        # Build SSV validators from events
        for event in events:
            event_operator_ids_set = set(event['args']['operatorIds'])

            if not ssv_operator_ids_set.issubset(event_operator_ids_set):
                continue

            ssv_validators.append(SSVValidator.from_event_data(event))

        # Save SSV validators to the database
        async with TransactionConnection() as conn:
            if ssv_validators:
                logger.info('Saving %d SSV validators', len(ssv_validators))
                await SSVValidatorCrud(conn).save_validators(ssv_validators)

            await CheckpointCrud(conn).update_checkpoint_block_number(
                checkpoint_type=CheckpointType.SSV_VALIDATOR_ADDED,
                block_number=to_block,
            )

        # Update the keystores with new SSV validators
        for keystore in self.keystores_map.values():
            await keystore.update_from_ssv_validators(
                ssv_validators=ssv_validators,
            )

    async def _get_from_block(self) -> BlockNumber:
        checkpoint_block = await CheckpointCrud().get_checkpoint_block_number(
            checkpoint_type=CheckpointType.SSV_VALIDATOR_ADDED
        )
        if checkpoint_block is not None:
            return BlockNumber(checkpoint_block + 1)

        cluster_genesis_block = await _get_ssv_cluster_genesis_block(
            ssv_operator_ids=self.ssv_operator_ids, to_block=await execution_client.eth.block_number
        )
        if cluster_genesis_block is None:
            raise RuntimeError('SSV cluster genesis block not found')

        return cluster_genesis_block


async def _get_ssv_cluster_genesis_block(
    ssv_operator_ids: list[int], to_block: BlockNumber
) -> BlockNumber | None:
    """
    Returns the first block at which all of the cluster operators existed
    """
    if not ssv_operator_ids:
        return None

    # Get genesis blocks for all SSV operators
    genesis_blocks = await asyncio.gather(
        *[
            _get_ssv_operator_genesis_block(ssv_operator_id, to_block)
            for ssv_operator_id in ssv_operator_ids
        ]
    )

    return max(genesis_blocks)


async def _get_ssv_operator_genesis_block(
    ssv_operator_id: int, to_block: BlockNumber | None
) -> BlockNumber:
    event = await ssv_registry_contract.get_last_operator_added_event(
        operator_id=ssv_operator_id, to_block=to_block
    )
    if event is None:
        raise RuntimeError(f'Genesis block for SSV operator {ssv_operator_id} not found')

    genesis_block = BlockNumber(event['blockNumber'])
    logger.info('Found genesis block %s for SSV operator %s', genesis_block, ssv_operator_id)

    return genesis_block
