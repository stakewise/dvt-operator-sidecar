import logging

from src.config import settings
from src.config.settings import OBOL, SSV
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.obol import ObolKeystore
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.keystores.ssv import SSVKeystore

logger = logging.getLogger(__name__)


async def load_keystore() -> BaseKeystore:
    if settings.remote_signer_url:
        remote_keystore = await RemoteSignerKeystore.load()
        logger.info(
            'Using remote signer at %s for %i public keys',
            settings.remote_signer_url,
            len(remote_keystore),
        )
        return remote_keystore

    if settings.cluster_type == OBOL:
        return await ObolKeystore.load()

    if settings.cluster_type == SSV:
        return await SSVKeystore.load()

    raise RuntimeError('No keystore or remote signer URL provided')
