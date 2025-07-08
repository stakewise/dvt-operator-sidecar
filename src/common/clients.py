from sw_utils import get_consensus_client, get_execution_client

from src.config import settings

execution_client = get_execution_client(
    [settings.execution_endpoint],
    timeout=settings.execution_timeout,
    retry_timeout=settings.execution_retry_timeout,
)
consensus_client = get_consensus_client(
    [settings.consensus_endpoint],
    timeout=settings.consensus_timeout,
    retry_timeout=settings.consensus_retry_timeout,
)
