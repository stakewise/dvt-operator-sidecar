import base64
import json
import logging
from dataclasses import dataclass

import milagro_bls_binding as bls
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from eth_account import Account
from eth_typing import BLSSignature, HexStr
from sw_utils import ConsensusFork, get_exit_message_signing_root
from web3 import Web3

from src.common.utils import to_chunks
from src.config import settings
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.typings import BLSPrivkey, Keys

logger = logging.getLogger(__name__)


class SSVKeystore(BaseKeystore):
    """
    Similar to LocalKeystore from Stakewise Operator, but:
    * keys are loaded from keyshares.json file
    * pubkey_to_share attribute added
    """

    keys: Keys

    def __init__(self, keys: Keys, pubkey_to_share: dict[HexStr, HexStr]):
        self.keys = keys
        self.pubkey_to_share = pubkey_to_share

    @staticmethod
    async def load() -> 'SSVKeystore':
        if settings.ssv_operator_id is None:
            raise RuntimeError('SSV_OPERATOR_ID must be set')
        if not settings.ssv_operator_key_file:
            raise RuntimeError('SSV_OPERATOR_KEY_FILE must be set')
        if not settings.ssv_operator_password_file:
            raise RuntimeError('SSV_OPERATOR_PASSWORD_FILE must be set')

        return SSVKeystore.load_as_operator(
            settings.ssv_operator_id,
            settings.ssv_operator_key_file,
            settings.ssv_operator_password_file,
        )

    @staticmethod
    def load_as_operator(
        ssv_operator_id: int, ssv_operator_key_file: str, ssv_operator_password_file: str
    ) -> 'SSVKeystore':
        operator_key = SSVOperator.load_key(ssv_operator_key_file, ssv_operator_password_file)

        if not settings.ssv_keyshares_file:
            raise RuntimeError('SSV_KEYSHARES_FILE must be set')
        key_shares = SSVKeySharesFile.load(
            settings.ssv_keyshares_file,
            ssv_operator_id,
            operator_key,
        )
        keys = Keys({})
        pubkey_to_share: dict[HexStr, HexStr] = {}

        for key_share in key_shares:
            keys[key_share.public_key_share] = key_share.key_share
            pubkey_to_share[key_share.public_key] = key_share.public_key_share

        return SSVKeystore(keys, pubkey_to_share)

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


class SSVKeySharesFile:
    @staticmethod
    def load(
        key_shares_path: str,
        operator_id: int,
        operator_key: RSA.RsaKey,
    ) -> list['SSVKeyShare']:
        """
        :param key_shares_path:
        :param operator_id:
        :param operator_key:
        :return:
        """
        logger.info('Loading keys from %s for operator %s...', key_shares_path, operator_id)
        with open(key_shares_path, encoding='ascii') as f:
            keyshares_json = json.load(f)

        key_shares: list[SSVKeyShare] = []

        for shares_item in keyshares_json['shares']:
            key_shares.append(SSVKeyShare.from_dict(shares_item, operator_id, operator_key))

        logger.info('Loaded %d keys', len(key_shares))
        return key_shares


@dataclass
class SSVKeyShare:
    key_share: BLSPrivkey
    public_key_share: HexStr
    public_key: HexStr

    @staticmethod
    def from_dict(shares_item: dict, operator_id: int, operator_key: RSA.RsaKey) -> 'SSVKeyShare':
        operators_data = shares_item['data']['operators']
        operator_count = len(operators_data)
        operator_index = SSVKeyShare.get_operator_index(operators_data, operator_id)

        shares_data = SSVSharesData.from_bytes(
            Web3.to_bytes(hexstr=HexStr(shares_item['payload']['sharesData'])), operator_count
        )

        public_key_share = shares_data.public_key_shares[operator_index]
        encrypted_key_share = shares_data.encrypted_key_shares[operator_index]
        key_share = SSVKeyShare.decrypt_rsa_pkcs1_v1_5(encrypted_key_share, operator_key)
        logger.debug('decrypted to %s', Web3.to_hex(key_share))

        derived_public_key_share = bls.SkToPk(key_share)
        if public_key_share != derived_public_key_share:
            raise RuntimeError('public key mismatch')

        public_key = shares_item['data']['publicKey']
        return SSVKeyShare(
            key_share=BLSPrivkey(key_share),
            public_key_share=Web3.to_hex(public_key_share),
            public_key=public_key,
        )

    @staticmethod
    def get_operator_index(operators_data: list[dict], operator_id: int) -> int:
        """
        Gets position of given operator in a list of cluster operators
        """
        for operator_index, operator_dict in enumerate(operators_data):
            if operator_id == operator_dict['id']:
                return operator_index
        raise RuntimeError('Can not get operator index')

    @staticmethod
    def decrypt_rsa_pkcs1_v1_5(data: bytes, rsa_key: RSA.RsaKey) -> bytes:
        """
        PKCS1 v1.5 is encryption scheme used for SSV key shares.
        It is default option in Golang rsa module
        https://pkg.go.dev/crypto/rsa#PrivateKey.Decrypt

        Python docs:
        https://pycryptodome.readthedocs.io/en/latest/src/cipher/pkcs1_v1_5.html
        """
        cipher_rsa = PKCS1_v1_5.new(rsa_key)

        # plain text is ascii-encoded hex string with 0x prefix
        # represents 32-bytes private key share
        expected_pt_len = 66

        # docs recommend using sentinel of the same length as expected_pt_len
        sentinel = get_random_bytes(expected_pt_len)

        # decrypt returns sentinel if decryption failed
        decrypted_data = cipher_rsa.decrypt(data, sentinel, expected_pt_len=expected_pt_len)
        if decrypted_data == sentinel:
            raise ValueError('can not decrypt')

        # convert from ascii to pure bytes
        return Web3.to_bytes(hexstr=HexStr(decrypted_data.decode('ascii')))


class SSVOperator:
    @staticmethod
    def load_key(operator_key_path: str, operator_password_path: str) -> RSA.RsaKey:
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
            raise RuntimeError('public key mismatch')

        return private_key

    @staticmethod
    def public_key_from_string(s: str) -> RSA.RsaKey:
        """
        :param s: operator public key, typically looks like 'LS0t...'
        """
        return RSA.import_key(base64.b64decode(s))


@dataclass
class SSVSharesData:
    """
    Represents key shares for single validator
    """

    public_key_shares: list[bytes]
    encrypted_key_shares: list[bytes]

    @staticmethod
    def from_bytes(data: bytes, operator_count: int) -> 'SSVSharesData':
        # offsets are in bytes
        signature_offset = 96  # BLS signature length
        public_key_length = 48  # BLS pubkey length
        # b64 encrypted key length is 256
        encrypted_key_length = 256

        pub_keys_offset = public_key_length * operator_count + signature_offset
        shares_expected_length = encrypted_key_length * operator_count + pub_keys_offset
        if len(data) != shares_expected_length:
            raise RuntimeError('unexpected shares data length')

        public_key_shares = to_chunks(data[signature_offset:pub_keys_offset], public_key_length)

        encrypted_key_shares = to_chunks(data[pub_keys_offset:], encrypted_key_length)

        return SSVSharesData(
            public_key_shares=list(public_key_shares),
            encrypted_key_shares=list(encrypted_key_shares),
        )
