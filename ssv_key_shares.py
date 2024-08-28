import json
from pathlib import Path
from typing import Iterator

from eth_account import Account
from web3 import Web3


import logging
logger = logging.getLogger(__name__)


def load_operator_key_via_eth_account(operator_key_path: str, operator_password_path: str):
    with open(operator_key_path, encoding='ascii') as f:
        jsn = json.load(f)

    with open(operator_password_path) as f:
        password = f.read().strip()

    private_key = Account.decrypt({
        'crypto': jsn,
        'version': 4,
    }, password)

    logger.info('private key bytes len %s', len(private_key))
    logger.info('json pubkey - %s', jsn['pubKey'])
    return private_key, jsn['pubKey']


def chunkify(items: list | range | bytes, size: int) -> Iterator[list | range | bytes]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def decrypt_key_shares(key_shares_path: str, operator_key: bytes, operator_index: int):
    """
    :param key_shares_path:
    :param operator_key:
    :param operator_index: 1-based
    :return:
    """
    with open(key_shares_path, encoding='ascii') as f:
        keyshares_json = json.load(f)

    # take first validator shares
    shares_data = Web3.to_bytes(hexstr=keyshares_json['shares'][0]['payload']['sharesData'])

    # offsets are in bytes
    operator_count = 4
    signature_offset = 96  # BLS signature length
    public_key_length = 48  # BLS pubkey length
    # b64 encrypted key length is 256
    encrypted_key_length = 256

    pub_keys_offset = public_key_length * operator_count + signature_offset
    shares_expected_length = encrypted_key_length * operator_count + pub_keys_offset

    signature = shares_data[:signature_offset]
    share_public_keys = chunkify(shares_data[signature_offset:pub_keys_offset], public_key_length)
    encrypted_keys = chunkify(shares_data[pub_keys_offset:], len(shares_data[pub_keys_offset:]) // operator_count)
