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

relayer_endpoint: str = config(
    'RELAYER_ENDPOINT', default=network_config.DEFAULT_DVT_RELAYER_ENDPOINT
)
relayer_timeout: int = config('RELAYER_TIMEOUT', cast=int, default=10)

execution_endpoint: str = config('EXECUTION_ENDPOINT', default='')
execution_timeout: int = config('EXECUTION_TIMEOUT', cast=int, default=30)
execution_retry_timeout: int = config('EXECUTION_RETRY_TIMEOUT', cast=int, default=60)

consensus_endpoint: str = config('CONSENSUS_ENDPOINT', default='')
consensus_timeout: int = config('CONSENSUS_TIMEOUT', cast=int, default=30)
consensus_retry_timeout: int = config('CONSENSUS_RETRY_TIMEOUT', cast=int, default=60)

database = config('DATABASE', default='dvt-operator-sidecar.db')

OBOL = 'OBOL'
SSV = 'SSV'
cluster_type: str = config('CLUSTER_TYPE', default='OBOL', cast=Choices([OBOL, SSV]))

obol_keystores_dir: str = config('OBOL_KEYSTORES_DIR', default='')
obol_keystores_dir_template: str = config('OBOL_KEYSTORES_DIR_TEMPLATE', default='')

obol_cluster_lock_file = config('OBOL_CLUSTER_LOCK_FILE', default='')

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

poll_interval: int = config('POLL_INTERVAL', cast=int, default=2)

ssv_api_base_url = 'https://api.ssv.network/api/v4'
ssv_api_timeout = 10

remote_signer_url: str = config('REMOTE_SIGNER_URL', default='')
remote_signer_timeout: int = config('REMOTE_SIGNER_TIMEOUT', cast=int, default=10)


def validate_settings() -> None:
    # Check OBOL_KEYSTORES_DIR
    if (
        not remote_signer_url
        and cluster_type == OBOL
        and not obol_keystores_dir
        and not obol_keystores_dir_template
    ):
        raise RuntimeError('OBOL_KEYSTORES_DIR or OBOL_KEYSTORES_DIR_TEMPLATE must be set')

    # Check cluster type for remote signer
    if remote_signer_url and cluster_type != OBOL:
        raise RuntimeError('Remote signer keystore is implemented for Obol only')

    # Check OBOL_CLUSTER_LOCK_FILE
    if cluster_type == OBOL and not obol_cluster_lock_file:
        raise RuntimeError('OBOL_CLUSTER_LOCK_FILE must be set')

    # Check SSV operator IDs
    if (
        not remote_signer_url
        and cluster_type == SSV
        and ssv_operator_id is None
        and not ssv_operator_ids
    ):
        raise RuntimeError('SSV_OPERATOR_ID or SSV_OPERATOR_IDS must be set')

    # Check SSV_OPERATOR_KEY_FILE
    if (
        not remote_signer_url
        and cluster_type == SSV
        and not ssv_operator_key_file
        and not ssv_operator_key_file_template
    ):
        raise RuntimeError('SSV_OPERATOR_KEY_FILE or SSV_OPERATOR_KEY_FILE_TEMPLATE must be set')

    # Check SSV_OPERATOR_PASSWORD_FILE
    if (
        not remote_signer_url
        and cluster_type == SSV
        and not ssv_operator_password_file
        and not ssv_operator_password_file_template
    ):
        raise RuntimeError(
            'SSV_OPERATOR_PASSWORD_FILE or SSV_OPERATOR_PASSWORD_FILE_TEMPLATE must be set'
        )

    # Check SSV operator key file template when running multiple SSV operators
    if (
        not remote_signer_url
        and cluster_type == SSV
        and ssv_operator_id is None
        and ssv_operator_ids
        and not ssv_operator_key_file_template
    ):
        raise RuntimeError(
            'SSV_OPERATOR_KEY_FILE_TEMPLATE must be set when running multiple SSV operators'
        )

    # Check SSV operator password file template when running multiple SSV operators
    if (
        not remote_signer_url
        and cluster_type == SSV
        and ssv_operator_id is None
        and ssv_operator_ids
        and not ssv_operator_password_file_template
    ):
        raise RuntimeError(
            'SSV_OPERATOR_PASSWORD_FILE_TEMPLATE must be set when running multiple SSV operators'
        )
