import base64
import json
import logging
from dataclasses import dataclass
from typing import cast

import milagro_bls_binding as bls
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from eth_account import Account
from eth_typing import BLSSignature, HexStr
from hexbytes import HexBytes
from sw_utils import ConsensusFork, get_exit_message_signing_root
from web3 import Web3

from src.common.setup_logging import ExtendedLogger
from src.common.utils import to_chunks
from src.config import settings
from src.ssv_operators.database import SSVValidatorCrud
from src.ssv_operators.typings import SSVValidator
from src.validators.keystores import ssv_api
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.typings import BLSPrivkey, Keys

logger = cast(ExtendedLogger, logging.getLogger(__name__))


class SSVKeystore(BaseKeystore):
    """
    Similar to LocalKeystore from Stakewise Operator, but:
    * keys are loaded from the database
    * new attributes added:
    - `ssv_operator_id`: SSV Operator id
    - `ssv_operator_key`: SSV Operator private key
    - `pubkey_to_share`: mapping from validator public key to its share public key
    """

    def __init__(
        self,
        ssv_operator_id: int,
        ssv_operator_key: RSA.RsaKey,
        keys: Keys,
        pubkey_to_share: dict[HexStr, HexStr],
    ):
        self.ssv_operator_id = ssv_operator_id
        self.ssv_operator_key = ssv_operator_key
        self.keys = keys
        self.pubkey_to_share = pubkey_to_share

    @staticmethod
    async def load() -> 'SSVKeystore':
        """
        Loads validator keys in the case of single operator-id (production setup).
        """
        if settings.ssv_operator_id is None:
            raise RuntimeError('SSV_OPERATOR_ID must be set')
        if not settings.ssv_operator_key_file:
            raise RuntimeError('SSV_OPERATOR_KEY_FILE must be set')
        if not settings.ssv_operator_password_file:
            raise RuntimeError('SSV_OPERATOR_PASSWORD_FILE must be set')

        return await SSVKeystore.load_as_operator(
            settings.ssv_operator_id,
            settings.ssv_operator_key_file,
            settings.ssv_operator_password_file,
        )

    @staticmethod
    async def load_as_operator(
        ssv_operator_id: int, ssv_operator_key_file: str, ssv_operator_password_file: str
    ) -> 'SSVKeystore':
        """
        Loads validator keys from the database,
        filters key shares related to a given operator.
        """
        operator_key = SSVOperator.load_key(ssv_operator_key_file, ssv_operator_password_file)
        await SSVOperator.check_operator_key(ssv_operator_id, operator_key)

        key_shares = await load_ssv_key_shares(
            ssv_operator_id,
            operator_key,
        )
        keys = Keys({})
        pubkey_to_share: dict[HexStr, HexStr] = {}

        for key_share in key_shares:
            keys[key_share.public_key_share] = key_share.key_share
            pubkey_to_share[key_share.public_key] = key_share.public_key_share

        return SSVKeystore(
            ssv_operator_id=ssv_operator_id,
            ssv_operator_key=operator_key,
            keys=keys,
            pubkey_to_share=pubkey_to_share,
        )

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

    async def update_from_ssv_validators(self, ssv_validators: list[SSVValidator]) -> None:
        """
        Updates the keystore with new SSV validators.
        This method is called when new SSV validators are added to the database.
        """
        if not ssv_validators:
            return

        logger.info(
            'Updating SSV keystore for operator %d with %d validators',
            self.ssv_operator_id,
            len(ssv_validators),
        )

        for validator in ssv_validators:
            key_share = SSVValidatorKeyShares.from_validator(
                validator=validator,
                operator_id=self.ssv_operator_id,
                operator_key=self.ssv_operator_key,
            )

            self.keys[key_share.public_key_share] = key_share.key_share
            self.pubkey_to_share[key_share.public_key] = key_share.public_key_share

        logger.info('SSV keystore updated')


async def load_ssv_key_shares(
    operator_id: int,
    operator_key: RSA.RsaKey,
) -> list['SSVValidatorKeyShares']:
    """
    Loads key shares from validators stored in DB.
    """
    logger.info('Loading SSV validator keys for operator %s...', operator_id)

    validators = await SSVValidatorCrud().get_validators()
    key_shares: list[SSVValidatorKeyShares] = []

    for validator in validators:
        key_shares.append(
            SSVValidatorKeyShares.from_validator(validator, operator_id, operator_key)
        )

    logger.info('Loaded %d keys', len(key_shares))
    return key_shares


@dataclass
class SSVValidatorKeyShares:
    """
    Represents key shares for a single validator
    """

    key_share: BLSPrivkey
    public_key_share: HexStr
    public_key: HexStr

    @staticmethod
    def from_validator(
        validator: SSVValidator, operator_id: int, operator_key: RSA.RsaKey
    ) -> 'SSVValidatorKeyShares':
        """
        Converts validator into SSVValidatorKeyShares object

        Reference for shares data parsing and decrypting:
        https://github.com/ssvlabs/ssv/blob/main/eth/eventhandler/handlers.go
        """
        operator_count = len(validator.operator_ids)

        try:
            operator_index = validator.operator_ids.index(operator_id)
        except ValueError as e:
            raise RuntimeError(f'SSV operator {operator_id} not found in validator') from e

        shares_data = SSVSharesData.from_hex(validator.shares_data, operator_count)

        public_key_share = shares_data.public_key_shares[operator_index]
        encrypted_key_share = shares_data.encrypted_key_shares[operator_index]
        key_share = SSVValidatorKeyShares.decrypt_rsa_pkcs1_v1_5(encrypted_key_share, operator_key)
        logger.debug('Decrypted key share: %r', key_share)

        derived_public_key_share = bls.SkToPk(key_share)
        if public_key_share != derived_public_key_share:
            raise RuntimeError('Public key mismatch')

        return SSVValidatorKeyShares(
            key_share=BLSPrivkey(key_share),
            public_key_share=Web3.to_hex(public_key_share),
            public_key=validator.public_key,
        )

    @staticmethod
    def decrypt_rsa_pkcs1_v1_5(data: bytes, rsa_key: RSA.RsaKey) -> HexBytes:
        """
        PKCS1 v1.5 is encryption scheme used for SSV key shares.
        It is default option in Golang rsa module
        https://pkg.go.dev/crypto/rsa#PrivateKey.Decrypt

        Python docs:
        https://pycryptodome.readthedocs.io/en/latest/src/cipher/pkcs1_v1_5.html
        """
        cipher_rsa = PKCS1_v1_5.new(rsa_key)

        # plain text is ascii-encoded hex string
        # represents 32-bytes private key share
        # 0x prefix:
        # * is present when generating keys alone
        # * is missing when generating via DKG
        sentinel_len = 64

        # docs recommend using sentinel of the same length as expected_pt_len
        sentinel = get_random_bytes(sentinel_len)

        # decrypt returns sentinel if decryption failed
        # Do not pass `expected_pt_len` because of uncertain behavior with 0x prefix
        decrypted_data = cipher_rsa.decrypt(data, sentinel)
        if decrypted_data == sentinel:
            raise ValueError('Can not decrypt validator key share')

        # convert from ascii to pure bytes
        decrypted_data_bytes = Web3.to_bytes(hexstr=HexStr(decrypted_data.decode('ascii')))

        return HexBytes(decrypted_data_bytes)


class SSVOperator:
    @staticmethod
    def load_key(operator_key_path: str, operator_password_path: str) -> RSA.RsaKey:
        """
        SSV operator key is stored in format similar to BLS keystore.
        Although this format does not strictly conform to EIP standard.
        Keystore contains RSA private key in PEM format.
        PEM string is unencrypted. So encryption is only on keystore level.
        See key file example in SSV docs:
        https://docs.ssv.network/operator-user-guides/operator-node/installation
        """
        if not settings.ssv_operator_key_file:
            raise RuntimeError('SSV_OPERATOR_KEY_FILE must be set')
        if not settings.ssv_operator_password_file:
            raise RuntimeError('SSV_OPERATOR_PASSWORD_FILE must be set')

        logger.info('Loading operator key from %s', operator_key_path)

        with open(operator_key_path, encoding='utf-8') as f:
            jsn = json.load(f)

        with open(operator_password_path, encoding='utf-8') as f:
            password = f.read().strip()

        # Convert json to format expected by `eth_account.Account`
        jsn_wrap = {
            'crypto': jsn,
            'version': 4,
        }
        private_key_pem = Account.decrypt(jsn_wrap, password)

        private_key = RSA.import_key(private_key_pem)
        public_key = private_key.public_key()

        # Additional check to ensure RSA key was parsed properly
        # Compare public key from json and the one derived from private key
        public_key_2 = SSVOperator.public_key_from_string(jsn['pubKey'])
        if public_key != public_key_2:
            raise RuntimeError('Public key mismatch')

        return private_key

    @staticmethod
    def public_key_from_string(s: str) -> RSA.RsaKey:
        """
        :param s: operator public key, base64 encoded, typically looks like 'LS0t...'
        """
        return RSA.import_key(base64.b64decode(s))

    @staticmethod
    async def check_operator_key(ssv_operator_id: int, operator_key: RSA.RsaKey) -> None:
        """
        Checks that `operator_key` belongs to operator `ssv_operator_id`.
        SSV API is used to fetch operator public key by id.

        :param ssv_operator_id: SSV Operator id
        :param operator_key: SSV Operator private key
        """
        logger.info('Checking SSV operator key for operator %d...', ssv_operator_id)
        try:
            operator_data = await ssv_api.get_operator(ssv_operator_id)
        except Exception as e:
            # skip checks in case of ssv api error
            logger.warning('SSV api error. Skip checking operator key. Error detail: %s', e)
            return

        public_key = operator_key.public_key()
        api_public_key = SSVOperator.public_key_from_string(operator_data['public_key'])

        if public_key != api_public_key:
            raise ValueError(f'Operator key does not belong to operator {ssv_operator_id}')


@dataclass
class SSVSharesData:
    """
    Represents key shares data for single validator.
    """

    public_key_shares: list[HexBytes]
    encrypted_key_shares: list[HexBytes]

    @staticmethod
    def from_hex(data_hex: HexStr, operator_count: int) -> 'SSVSharesData':
        """
        Parses shares data string into SSVSharesData object.
        No decryption here, just parsing.
        """
        data = HexBytes(Web3.to_bytes(hexstr=data_hex))

        # offsets are in bytes
        signature_offset = 96  # BLS signature length
        public_key_length = 48  # BLS pubkey length
        # b64 encrypted key length is 256
        encrypted_key_length = 256

        pub_keys_offset = public_key_length * operator_count + signature_offset
        shares_expected_length = encrypted_key_length * operator_count + pub_keys_offset
        if len(data) != shares_expected_length:
            raise RuntimeError('Unexpected shares data length')

        public_key_shares = to_chunks(data[signature_offset:pub_keys_offset], public_key_length)

        encrypted_key_shares = to_chunks(data[pub_keys_offset:], encrypted_key_length)

        return SSVSharesData(
            public_key_shares=list(public_key_shares),
            encrypted_key_shares=list(encrypted_key_shares),
        )
