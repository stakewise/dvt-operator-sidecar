from dataclasses import asdict, dataclass

from sw_utils.networks import CHIADO, GNOSIS, HOODI, MAINNET
from sw_utils.networks import NETWORKS as BASE_NETWORKS
from sw_utils.networks import BaseNetworkConfig


@dataclass
class NetworkConfig(BaseNetworkConfig):
    DEFAULT_DVT_RELAYER_ENDPOINT: str


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **asdict(BASE_NETWORKS[MAINNET]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://mainnet-dvt-relayer.stakewise.io',
    ),
    HOODI: NetworkConfig(
        **asdict(BASE_NETWORKS[HOODI]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://hoodi-dvt-relayer.stakewise.io',
    ),
    GNOSIS: NetworkConfig(
        **asdict(BASE_NETWORKS[GNOSIS]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://gnosis-dvt-relayer.stakewise.io',
    ),
    CHIADO: NetworkConfig(
        **asdict(BASE_NETWORKS[CHIADO]),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://chiado-dvt-relayer.stakewise.io',
    ),
}
