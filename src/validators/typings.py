from enum import Enum

from eth_typing import HexAddress, HexStr
from sw_utils.signing import get_v1_withdrawal_credentials, get_v2_withdrawal_credentials
from sw_utils.typings import Bytes32


class ValidatorType(Enum):
    V1 = '0x01'
    V2 = '0x02'


def get_withdrawal_credentials(vault: HexStr, validator_type: ValidatorType) -> Bytes32:
    vault_address = HexAddress(vault)
    if validator_type == ValidatorType.V1:
        return get_v1_withdrawal_credentials(vault_address)
    return get_v2_withdrawal_credentials(vault_address)
