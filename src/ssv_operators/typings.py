from dataclasses import dataclass

from eth_typing import HexStr
from web3 import Web3
from web3.types import EventData


@dataclass
class SSVValidator:
    # full (aggregated) validator public key
    public_key: HexStr

    # cluster operator IDs
    operator_ids: list[int]

    # validator private keys, encrypted with operator keys
    shares_data: HexStr

    @staticmethod
    def from_event_data(event_data: EventData) -> 'SSVValidator':
        return SSVValidator(
            public_key=Web3.to_hex(event_data['args']['publicKey']),
            operator_ids=event_data['args']['operatorIds'],
            shares_data=Web3.to_hex(event_data['args']['shares']),
        )
