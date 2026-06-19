import abc

import milagro_bls_binding as bls
from eth_typing import BLSSignature, ChecksumAddress, HexStr
from sw_utils import ConsensusFork, get_exit_message_signing_root
from sw_utils.signing import (
    DepositMessage,
    compute_deposit_domain,
    compute_signing_root,
)
from web3 import Web3

from src.config import settings
from src.validators.keystores.typings import Keys
from src.validators.typings import (
    PublicKeyShare,
    ValidatorType,
    get_withdrawal_credentials,
)


class BaseKeystore(abc.ABC):
    def __init__(
        self,
        pubkey_to_share: dict[HexStr, HexStr],
        pubkey_to_all_shares: dict[HexStr, list[PublicKeyShare]],
    ) -> None:
        # Mapping from validator public key to its share public key
        self.pubkey_to_share = pubkey_to_share

        # Reverse mapping from share public key to validator public key
        self.share_to_pubkey = {v: k for k, v in pubkey_to_share.items()}

        # Mapping from validator public key to all operators' public key shares
        # (each carrying its share index). Sent to the relayer so it can reconstruct
        # the full validator public key and validate each submitted share by index.
        self.pubkey_to_all_shares = pubkey_to_all_shares

    @staticmethod
    @abc.abstractmethod
    async def load() -> 'BaseKeystore':
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
        self,
        public_key_share: HexStr,
        vault: ChecksumAddress,
        amount: int,
        validator_type: ValidatorType,
    ) -> BLSSignature:
        raise NotImplementedError


class LocalKeystore(BaseKeystore):
    def __init__(
        self,
        pubkey_share_to_privkey_share: Keys,
        pubkey_to_share: dict[HexStr, HexStr],
        pubkey_to_all_shares: dict[HexStr, list[PublicKeyShare]],
    ) -> None:
        super().__init__(pubkey_to_share, pubkey_to_all_shares)
        self.pubkey_share_to_privkey_share = pubkey_share_to_privkey_share

    def __len__(self) -> int:
        return len(self.pubkey_share_to_privkey_share)

    async def get_exit_signature(
        self, validator_index: int, public_key_share: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        private_key_share = self.pubkey_share_to_privkey_share[public_key_share]
        fork = fork or settings.network_config.SHAPELLA_FORK
        genesis_validators_root = settings.network_config.GENESIS_VALIDATORS_ROOT

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=genesis_validators_root,
            fork=fork,
        )

        return BLSSignature(bls.Sign(private_key_share, message))

    async def get_deposit_signature(
        self,
        public_key_share: HexStr,
        vault: ChecksumAddress,
        amount: int,
        validator_type: ValidatorType,
    ) -> BLSSignature:
        private_key_share = self.pubkey_share_to_privkey_share[public_key_share]
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
        return BLSSignature(bls.Sign(private_key_share, signing_root))
