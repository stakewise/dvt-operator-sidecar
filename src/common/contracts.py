import json
import logging
import os
from functools import cached_property

from eth_typing import BlockNumber
from web3.contract import AsyncContract
from web3.contract.async_contract import (
    AsyncContractEvent,
    AsyncContractEvents,
    AsyncContractFunctions,
)
from web3.types import ChecksumAddress, EventData

from src.common.clients import execution_client
from src.config import settings
from src.config.settings import network_config

logger = logging.getLogger(__name__)


class ContractWrapper:
    abi_path: str = ''

    def __init__(self, address: ChecksumAddress):
        self.address = address

    @cached_property
    def contract(self) -> AsyncContract:
        current_dir = os.path.dirname(__file__)
        with open(os.path.join(current_dir, self.abi_path), encoding='utf-8') as f:
            abi = json.load(f)
        return execution_client.eth.contract(abi=abi, address=self.address)

    @property
    def functions(self) -> AsyncContractFunctions:
        return self.contract.functions

    @property
    def events(self) -> AsyncContractEvents:
        return self.contract.events

    @property
    def events_blocks_range_interval(self) -> int:
        return 43200 // network_config.SECONDS_PER_BLOCK  # 12 hrs

    async def _get_last_event(
        self,
        event: type[AsyncContractEvent],
        from_block: BlockNumber,
        to_block: BlockNumber,
        argument_filters: dict | None = None,
    ) -> EventData | None:
        blocks_range = self.events_blocks_range_interval
        cur_to_block: int = to_block

        while cur_to_block >= from_block:
            cur_from_block = max(cur_to_block - blocks_range + 1, from_block)
            logger.debug(
                'Fetching events %s from block %s to %s',
                event.event_name,
                cur_from_block,
                cur_to_block,
            )
            events = await event.get_logs(
                fromBlock=BlockNumber(cur_from_block),
                toBlock=BlockNumber(cur_to_block),
                argument_filters=argument_filters,
            )
            if events:
                return events[-1]
            cur_to_block -= blocks_range
        return None

    async def _get_events(
        self,
        event: type[AsyncContractEvent],
        from_block: BlockNumber,
        to_block: BlockNumber,
        argument_filters: dict | None = None,
    ) -> list[EventData]:
        events: list[EventData] = []
        blocks_range = self.events_blocks_range_interval
        cur_from_block: int = from_block

        while to_block >= cur_from_block:
            cur_to_block = min(cur_from_block + blocks_range - 1, to_block)
            logger.debug(
                'Fetching events %s from block %s to %s',
                event.event_name,
                cur_from_block,
                cur_to_block,
            )
            range_events = await event.get_logs(
                fromBlock=BlockNumber(cur_from_block),
                toBlock=BlockNumber(cur_to_block),
                argument_filters=argument_filters,
            )
            if range_events:
                events.extend(range_events)
            cur_from_block += blocks_range

        return events


class SSVRegistryContract(ContractWrapper):
    abi_path = 'abi/ISSVRegistry.json'

    async def get_last_operator_added_event(
        self,
        operator_id: int,
        from_block: BlockNumber | None = None,
        to_block: BlockNumber | None = None,
    ) -> EventData | None:
        """Fetches the last OperatorAdded event."""
        return await self._get_last_event(
            self.events.OperatorAdded,  # type: ignore
            from_block=from_block or settings.network_config.SSV_GENESIS_BLOCK,
            to_block=to_block or await execution_client.eth.get_block_number(),
            argument_filters={'operatorId': operator_id},
        )

    async def get_validator_added_events(
        self, from_block: BlockNumber | None = None, to_block: BlockNumber | None = None
    ) -> list[EventData]:
        """Fetches all ValidatorAdded events."""
        return await self._get_events(
            self.events.ValidatorAdded,  # type: ignore
            from_block=from_block or settings.network_config.SSV_GENESIS_BLOCK,
            to_block=to_block or await execution_client.eth.get_block_number(),
        )


ssv_registry_contract = SSVRegistryContract(settings.network_config.SSV_REGISTRY_CONTRACT_ADDRESS)
