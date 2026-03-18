from enum import Enum
from typing import Annotated, Any

from eth_typing import ChecksumAddress, HexStr
from pydantic import BaseModel, BeforeValidator
from sw_utils.signing import (
    get_v1_withdrawal_credentials,
    get_v2_withdrawal_credentials,
)
from sw_utils.typings import Bytes32
from web3 import Web3


def to_checksum_address(v: Any) -> ChecksumAddress:
    return Web3.to_checksum_address(v)


ChecksumAddressField = Annotated[ChecksumAddress, BeforeValidator(to_checksum_address)]


class ValidatorType(Enum):
    V1 = '0x01'
    V2 = '0x02'


class RelayerValidator(BaseModel):
    public_key: HexStr
    vault: ChecksumAddressField
    amount: int
    validator_type: ValidatorType
    validator_index: int
    share_indexes_ready: list[int]


def get_withdrawal_credentials(
    vault_address: ChecksumAddress, validator_type: ValidatorType
) -> Bytes32:
    if validator_type == ValidatorType.V1:
        return get_v1_withdrawal_credentials(vault_address)
    if validator_type == ValidatorType.V2:
        return get_v2_withdrawal_credentials(vault_address)
    raise ValueError(f'Unsupported validator type: {validator_type.value}')
