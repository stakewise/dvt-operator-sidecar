from dataclasses import dataclass

from eth_typing import HexStr
from sw_utils import ConsensusFork
from sw_utils.typings import Bytes32
from web3 import Web3

MAINNET = 'mainnet'
GNOSIS = 'gnosis'
HOLESKY = 'holesky'
CHIADO = 'chiado'

GNO_NETWORKS = [GNOSIS, CHIADO]


@dataclass
class NetworkConfig:
    SHAPELLA_FORK_VERSION: bytes
    SHAPELLA_EPOCH: int
    GENESIS_VALIDATORS_ROOT: Bytes32

    @property
    def SHAPELLA_FORK(self) -> ConsensusFork:
        return ConsensusFork(
            version=self.SHAPELLA_FORK_VERSION,
            epoch=self.SHAPELLA_EPOCH,
        )


NETWORKS = {
    MAINNET: NetworkConfig(
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000000')),
        SHAPELLA_EPOCH=194048,
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95')
            )
        ),
    ),
    HOLESKY: NetworkConfig(
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x04017000')),
        SHAPELLA_EPOCH=256,
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1')
            )
        ),
    ),
    GNOSIS: NetworkConfig(
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000064')),
        SHAPELLA_EPOCH=648704,
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47')
            )
        ),
    ),
    CHIADO: NetworkConfig(
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x0300006f')),
        SHAPELLA_EPOCH=244224,
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e')
            )
        ),
    ),
}