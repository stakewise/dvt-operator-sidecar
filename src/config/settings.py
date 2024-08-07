from pathlib import Path

from decouple import config

from src.config.networks import NETWORKS, NetworkConfig

network: str = config('NETWORK')
network_config: NetworkConfig = NETWORKS[network]

LOG_PLAIN = 'plain'
LOG_JSON = 'json'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

log_level: str = config('LOG_LEVEL', default='INFO')
log_format: str = config('LOG_FORMAT', default=LOG_PLAIN)

sentry_dsn: str = config('SENTRY_DSN', default='')
sentry_environment = config('SENTRY_ENVIRONMENT', default='')

relayer_endpoint: str = config('RELAYER_ENDPOINT')
relayer_timeout: int = config('RELAYER_TIMEOUT', cast=int, default=10)

keystores_dir = Path(config('KEYSTORES_DIR'))

cluster_lock_path = Path(config('CLUSTER_LOCK_PATH'))

share_index: int = config('SHARE_INDEX', cast=int)

poll_interval: int = config('POLL_INTERVAL', cast=int, default=1)
