from pathlib import Path

from decouple import Choices, Csv, config

from src.config.networks import NETWORKS

network: str = config('NETWORK', cast=Choices(list(NETWORKS.keys())))
network_config = NETWORKS[network]

LOG_PLAIN = 'plain'
LOG_JSON = 'json'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

log_level: str = config('LOG_LEVEL', default='INFO')
log_format: str = config('LOG_FORMAT', default=LOG_PLAIN, cast=Choices([LOG_PLAIN, LOG_JSON]))
verbose: bool = config('VERBOSE', default=False, cast=bool)

sentry_dsn: str = config('SENTRY_DSN', default='')
sentry_environment = config('SENTRY_ENVIRONMENT', default='')

relayer_endpoint: str = config('RELAYER_ENDPOINT')
relayer_timeout: int = config('RELAYER_TIMEOUT', cast=int, default=10)

OBOL = 'OBOL'
SSV = 'SSV'
cluster_type: str = config('CLUSTER_TYPE', default='OBOL', cast=Choices([OBOL, SSV]))

obol_keystores_dir: str = config('OBOL_KEYSTORES_DIR', default='')
obol_keystores_dir_template: str = config('OBOL_KEYSTORES_DIR_TEMPLATE', default='')

obol_cluster_lock_file = Path(config('OBOL_CLUSTER_LOCK_FILE'), default='')

obol_node_index: int | None = config(
    'OBOL_NODE_INDEX', cast=lambda x: int(x) if x != '' else None, default=''
)
obol_node_indexes: list[int] = config('OBOL_NODE_INDEXES', cast=Csv(int), default='')

ssv_operator_key_file: str = config('SSV_OPERATOR_KEY_FILE', default='')
ssv_operator_password_file: str = config('SSV_OPERATOR_PASSWORD_FILE', default='')

ssv_operator_key_file_template: str = config('SSV_OPERATOR_KEY_FILE_TEMPLATE', default='')
ssv_operator_password_file_template: str = config('SSV_OPERATOR_PASSWORD_FILE_TEMPLATE', default='')

ssv_operator_id: int | None = config(
    'SSV_OPERATOR_ID', cast=lambda x: int(x) if x != '' else None, default=''
)
ssv_operator_ids: list[int] = config('SSV_OPERATOR_IDS', cast=Csv(int), default='')

ssv_keyshares_file: str = config('SSV_KEYSHARES_FILE', default='')
poll_interval: int = config('POLL_INTERVAL', cast=int, default=2)

remote_signer_url: str = config('remote_signer_url', default='')
remote_signer_timeout: int = config('REMOTE_SIGNER_TIMEOUT', cast=int, default=10)

# validations

if (
    not remote_signer_url
    and cluster_type == OBOL
    and not obol_keystores_dir
    and not obol_keystores_dir_template
):
    raise RuntimeError('OBOL_KEYSTORES_DIR or OBOL_KEYSTORES_DIR_TEMPLATE must be set')

if (
    not remote_signer_url
    and cluster_type == SSV
    and not ssv_operator_key_file
    and not ssv_operator_key_file_template
):
    raise RuntimeError('SSV_OPERATOR_KEY_FILE or SSV_OPERATOR_KEY_FILE_TEMPLATE must be set')

if (
    not remote_signer_url
    and cluster_type == SSV
    and not ssv_operator_password_file
    and not ssv_operator_password_file_template
):
    raise RuntimeError(
        'SSV_OPERATOR_PASSWORD_FILE or SSV_OPERATOR_PASSWORD_FILE_TEMPLATE must be set'
    )
