import json
import logging
from os import listdir
from os.path import isfile
from pathlib import Path
from typing import cast

import milagro_bls_binding as bls
from eth_typing import BLSSignature, HexStr
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils import ConsensusFork, get_exit_message_signing_root
from web3 import Web3

from src.common.setup_logging import ExtendedLogger
from src.config import settings
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.exceptions import KeystoreException
from src.validators.keystores.typings import BLSPrivkey, Keys, KeystoreFile

logger = cast(ExtendedLogger, logging.getLogger(__name__))


class ObolKeystore(BaseKeystore):
    """
    Similar to LocalKeystore from Stakewise Operator.
    Also pubkey_to_share attribute is filled using cluster lock file.
    """

    keys: Keys

    def __init__(self, keys: Keys, pubkey_to_share: dict[HexStr, HexStr]):
        self.keys = keys
        self.pubkey_to_share = pubkey_to_share

    @staticmethod
    async def load() -> 'ObolKeystore':
        if not settings.obol_keystores_dir:
            raise RuntimeError('OBOL_KEYSTORES_DIR must be set')
        if settings.obol_node_index is None:
            raise RuntimeError('OBOL_NODE_INDEX must be set')
        return await ObolKeystore.load_from_dir(
            Path(settings.obol_keystores_dir), settings.obol_node_index
        )

    @staticmethod
    async def load_from_dir(keystores_dir: Path, node_index: int) -> 'ObolKeystore':
        """Extracts private keys from the keys."""
        keystore_files = ObolKeystore.list_keystore_files(keystores_dir)
        logger.info('Loading keys from %s...', keystores_dir)
        results = [
            ObolKeystore._process_keystore_file(keystore_file, keystores_dir)
            for keystore_file in keystore_files
        ]
        keys = dict(results)

        logger.info('Loaded %d keys', len(keys))

        pubkey_to_share = ObolKeystore.get_pubkey_to_share(node_index)
        return ObolKeystore(Keys(keys), pubkey_to_share)

    @staticmethod
    def load_cluster_lock() -> dict:
        return json.load(open(settings.obol_cluster_lock_file, encoding='ascii'))

    @staticmethod
    def get_pubkey_to_share(node_index: int) -> dict[HexStr, HexStr]:
        cluster_lock = ObolKeystore.load_cluster_lock()

        pub_key_to_share = {}
        for dv in cluster_lock['distributed_validators']:
            public_key = dv['distributed_public_key']
            public_key_share = dv['public_shares'][node_index]
            pub_key_to_share[public_key] = public_key_share

        return pub_key_to_share

    def __bool__(self) -> bool:
        return len(self.keys) > 0

    def __contains__(self, public_key: HexStr) -> bool:
        return public_key in self.keys

    def __len__(self) -> int:
        return len(self.keys)

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        private_key = self.keys[public_key]
        fork = fork or settings.network_config.SHAPELLA_FORK
        genesis_validators_root = settings.network_config.GENESIS_VALIDATORS_ROOT

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=genesis_validators_root,
            fork=fork,
        )

        return bls.Sign(private_key, message)

    @property
    def public_keys(self) -> list[HexStr]:
        return list(self.keys.keys())

    @staticmethod
    def list_keystore_files(keystores_dir: Path) -> list[KeystoreFile]:
        keystores_password_dir = keystores_dir

        res: list[KeystoreFile] = []
        for f in listdir(keystores_dir):
            if not (isfile(keystores_dir / f) and f.startswith('keystore') and f.endswith('.json')):
                continue

            password_file = keystores_password_dir / f.replace('.json', '.txt')

            password = ObolKeystore._load_keystores_password(password_file)
            res.append(KeystoreFile(name=f, password=password, password_file=password_file))

        return res

    @staticmethod
    def _process_keystore_file(
        keystore_file: KeystoreFile, keystore_path: Path
    ) -> tuple[HexStr, BLSPrivkey]:
        file_name = keystore_file.name
        keystores_password = keystore_file.password
        file_path = keystore_path / file_name

        try:
            keystore = ScryptKeystore.from_file(str(file_path))
        except BaseException as e:
            raise KeystoreException(f'Invalid keystore format in file "{file_name}"') from e

        try:
            private_key = BLSPrivkey(keystore.decrypt(keystores_password))
        except BaseException as e:
            raise KeystoreException(f'Invalid password for keystore "{file_name}"') from e
        public_key = Web3.to_hex(bls.SkToPk(private_key))
        return public_key, private_key

    @staticmethod
    def _load_keystores_password(password_path: Path) -> str:
        with open(password_path, 'r', encoding='utf-8') as f:
            return f.read().strip()
