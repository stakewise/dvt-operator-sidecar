import dataclasses
import json
import logging
from dataclasses import dataclass
from typing import cast

import milagro_bls_binding as bls
from aiohttp import ClientSession, ClientTimeout
from eth_typing import BLSPubkey, BLSSignature, HexStr
from sw_utils import get_exit_message_signing_root
from sw_utils.common import urljoin
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.setup_logging import ExtendedLogger
from src.config import settings
from src.validators.keystores.base import BaseKeystore

logger = cast(ExtendedLogger, logging.getLogger(__name__))


@dataclass
class Fork:
    previous_version: HexStr
    current_version: HexStr
    epoch: int


@dataclass
class ForkInfo:
    fork: Fork
    genesis_validators_root: HexStr


@dataclass
class VoluntaryExitMessage:
    epoch: int
    validator_index: int


@dataclass
class VoluntaryExitRequestModel:
    fork_info: ForkInfo
    signing_root: HexStr
    type: str
    voluntary_exit: VoluntaryExitMessage


class ObolRemoteKeystore(BaseKeystore):
    """
    Similar to RemoteKeystore from Stakewise Operator.
    Also pubkey_to_share attribute is filled using cluster lock file.
    """

    def __init__(self, public_keys: list[HexStr], pubkey_to_share: dict[HexStr, HexStr]):
        self._public_keys = public_keys
        self.pubkey_to_share = pubkey_to_share

    @staticmethod
    async def load() -> 'BaseKeystore':
        if settings.obol_node_index is None:
            raise RuntimeError('OBOL_NODE_INDEX must be set')

        public_keys = await ObolRemoteKeystore._get_remote_signer_public_keys()
        pubkey_to_share = ObolRemoteKeystore.get_pubkey_to_share(settings.obol_node_index)
        return ObolRemoteKeystore(public_keys, pubkey_to_share)

    @staticmethod
    def load_cluster_lock() -> dict:
        return json.load(open(settings.obol_cluster_lock_file, encoding='ascii'))

    @staticmethod
    def get_pubkey_to_share(node_index: int) -> dict[HexStr, HexStr]:
        cluster_lock = ObolRemoteKeystore.load_cluster_lock()

        pub_key_to_share = {}
        for dv in cluster_lock['distributed_validators']:
            public_key = dv['distributed_public_key']
            public_key_share = dv['public_shares'][node_index]
            pub_key_to_share[public_key] = public_key_share

        return pub_key_to_share

    def __bool__(self) -> bool:
        return bool(self._public_keys)

    def __len__(self) -> int:
        return len(self._public_keys)

    def __contains__(self, public_key: HexStr) -> bool:
        return public_key in self._public_keys

    @property
    def public_keys(self) -> list[HexStr]:
        return self._public_keys

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        fork = fork or settings.network_config.SHAPELLA_FORK

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))

        exit_signature = await self._sign_exit_request(
            public_key_bytes, validator_index, fork, message
        )

        bls.Verify(BLSPubkey(Web3.to_bytes(hexstr=public_key)), message, exit_signature)
        return exit_signature

    @staticmethod
    async def _get_remote_signer_public_keys() -> list[HexStr]:
        signer_url = urljoin(settings.remote_signer_url, '/api/v1/eth2/publicKeys')
        async with ClientSession(timeout=ClientTimeout(settings.remote_signer_timeout)) as session:
            response = await session.get(signer_url)

            response.raise_for_status()
            return await response.json()

    @staticmethod
    async def _sign_exit_request(
        public_key: BLSPubkey,
        validator_index: int,
        fork: ConsensusFork,
        message: bytes,
    ) -> BLSSignature:
        data = VoluntaryExitRequestModel(
            fork_info=ForkInfo(
                fork=Fork(
                    previous_version=HexStr(fork.version.hex()),
                    current_version=HexStr(fork.version.hex()),
                    epoch=fork.epoch,
                ),
                genesis_validators_root=HexStr(
                    settings.network_config.GENESIS_VALIDATORS_ROOT.hex()
                ),
            ),
            signing_root=HexStr(message.hex()),
            type='VOLUNTARY_EXIT',
            voluntary_exit=VoluntaryExitMessage(epoch=fork.epoch, validator_index=validator_index),
        )

        signer_url = urljoin(settings.remote_signer_url, f'/api/v1/eth2/sign/0x{public_key.hex()}')
        async with ClientSession(timeout=ClientTimeout(settings.remote_signer_timeout)) as session:
            response = await session.post(signer_url, json=dataclasses.asdict(data))

            if response.status == 404:
                # Pubkey not present on remote signer side
                raise RuntimeError(
                    f'Failed to get signature for {public_key.hex()}.'
                    f' Is this public key present in the remote signer?'
                )

            response.raise_for_status()

            signature = (await response.json())['signature']
        return BLSSignature(Web3.to_bytes(hexstr=signature))
