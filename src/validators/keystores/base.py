import abc

import milagro_bls_binding as bls
from eth_typing import BLSSignature, HexStr
from sw_utils import ConsensusFork, get_exit_message_signing_root
from sw_utils.signing import (
    DepositMessage,
    compute_deposit_domain,
    compute_signing_root,
)
from web3 import Web3

from src.config import settings
from src.validators.keystores.typings import Keys
from src.validators.typings import ValidatorType, get_withdrawal_credentials


class BaseKeystore(abc.ABC):
    pubkey_to_share: dict[HexStr, HexStr]

    @staticmethod
    @abc.abstractmethod
    async def load() -> 'BaseKeystore':
        raise NotImplementedError

    @abc.abstractmethod
    def __bool__(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def __contains__(self, public_key: HexStr) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def __len__(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_exit_signature(
        self, validator_index: int, public_key_share: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_deposit_signature(
        self, public_key_share: HexStr, vault: HexStr, amount: int, validator_type: ValidatorType
    ) -> BLSSignature:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def public_keys(self) -> list[HexStr]:
        raise NotImplementedError


class LocalKeystoreMixin:
    keys: Keys
    share_to_pubkey: dict[HexStr, HexStr]

    async def get_exit_signature(
        self, validator_index: int, public_key_share: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        private_key_share = self.keys[public_key_share]
        fork = fork or settings.network_config.SHAPELLA_FORK
        genesis_validators_root = settings.network_config.GENESIS_VALIDATORS_ROOT

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=genesis_validators_root,
            fork=fork,
        )

        return bls.Sign(private_key_share, message)

    async def get_deposit_signature(
        self, public_key_share: HexStr, vault: HexStr, amount: int, validator_type: ValidatorType
    ) -> BLSSignature:
        private_key_share = self.keys[public_key_share]
        public_key = self.share_to_pubkey[public_key_share]

        # Build deposit message
        withdrawal_credentials = get_withdrawal_credentials(vault, validator_type)
        deposit_message = DepositMessage(
            pubkey=Web3.to_bytes(hexstr=public_key),
            withdrawal_credentials=withdrawal_credentials,
            amount=amount,
        )
        # Sign deposit message
        domain = compute_deposit_domain(settings.network_config.GENESIS_FORK_VERSION)
        signing_root = compute_signing_root(deposit_message, domain)
        return bls.Sign(private_key_share, signing_root)
