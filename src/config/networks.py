from dataclasses import asdict, dataclass

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.networks import CHIADO, GNOSIS, HOODI, MAINNET
from sw_utils.networks import NETWORKS as BASE_NETWORKS
from sw_utils.networks import BaseNetworkConfig
from web3 import Web3


@dataclass
class NetworkConfig(BaseNetworkConfig):
    DEFAULT_DVT_RELAYER_ENDPOINT: str
    SSV_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress
    SSV_GENESIS_BLOCK: BlockNumber


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **asdict(BASE_NETWORKS[MAINNET]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://mainnet-dvt-relayer.stakewise.io',
        SSV_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1'
        ),
        SSV_GENESIS_BLOCK=BlockNumber(17507487),
    ),
    HOODI: NetworkConfig(
        **asdict(BASE_NETWORKS[HOODI]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://hoodi-dvt-relayer.stakewise.io',
        SSV_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x58410Bef803ECd7E63B23664C586A6DB72DAf59c'
        ),
        SSV_GENESIS_BLOCK=BlockNumber(1065),
    ),
    GNOSIS: NetworkConfig(
        **asdict(BASE_NETWORKS[GNOSIS]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://gnosis-dvt-relayer.stakewise.io',
        SSV_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        SSV_GENESIS_BLOCK=BlockNumber(0),
    ),
    CHIADO: NetworkConfig(
        **asdict(BASE_NETWORKS[CHIADO]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://chiado-dvt-relayer.stakewise.io',
        SSV_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        SSV_GENESIS_BLOCK=BlockNumber(0),
    ),
}
