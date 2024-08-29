import base64
import json
import logging
from typing import Iterator

import milagro_bls_binding as bls
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from eth_account import Account
from eth_typing import HexStr
from web3 import Web3

logger = logging.getLogger(__name__)


def load_operator_key(operator_key_path: str, operator_password_path: str) -> RSA.RsaKey:
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
    public_key_2 = RSA.import_key(base64.b64decode(jsn['pubKey']))
    if public_key != public_key_2:
        raise RuntimeError('public key mismatch')

    return private_key


def to_chunks(items: list | range | bytes, size: int) -> Iterator[list | range | bytes]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


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


def decrypt_key_shares(key_shares_path: str, operator_keys: list[RSA.RsaKey]) -> list[bytes]:
    """
    :param key_shares_path:
    :param operator_keys:
    :return:
    """
    with open(key_shares_path, encoding='ascii') as f:
        keyshares_json = json.load(f)

    # take first validator shares
    shares_data = Web3.to_bytes(hexstr=keyshares_json['shares'][0]['payload']['sharesData'])

    # cluster size
    operator_count = 4

    # offsets are in bytes
    signature_offset = 96  # BLS signature length
    public_key_length = 48  # BLS pubkey length
    # b64 encrypted key length is 256
    encrypted_key_length = 256

    pub_keys_offset = public_key_length * operator_count + signature_offset
    shares_expected_length = encrypted_key_length * operator_count + pub_keys_offset
    if len(shares_data) != shares_expected_length:
        raise RuntimeError('unexpected shares data length')

    # signature = shares_data[:signature_offset]
    share_public_keys = to_chunks(shares_data[signature_offset:pub_keys_offset], public_key_length)

    encrypted_key_shares: Iterator[bytes] = to_chunks(shares_data[pub_keys_offset:], operator_count)  # type: ignore

    key_shares: list[bytes] = []

    # todo: check signature
    for (
            operator_key,
            encrypted_key_share,
            public_key_share
    ) in zip(
            operator_keys,
            encrypted_key_shares,
            share_public_keys
    ):
        key_share = decrypt_rsa_pkcs1_v1_5(encrypted_key_share, operator_key)
        logger.debug('decrypted to %s', Web3.to_hex(key_share))

        derived_public_key_share = bls.SkToPk(key_share)
        if public_key_share != derived_public_key_share:
            raise RuntimeError('public key mismatch')

        key_shares.append(key_share)

    return key_shares
