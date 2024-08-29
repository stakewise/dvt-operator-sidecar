from dataclasses import dataclass
from pathlib import Path
from typing import NewType

from eth_typing import HexStr

BLSPrivkey = NewType('BLSPrivkey', bytes)


@dataclass
class KeystoreFile:
    name: str
    password: str
    password_file: Path


Keys = NewType('Keys', dict[HexStr, BLSPrivkey])
