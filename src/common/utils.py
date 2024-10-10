import asyncio
import functools
from pathlib import Path
from typing import Iterator, overload

import tomli


@overload
def to_chunks(items: list, size: int) -> Iterator[list]:
    ...


@overload
def to_chunks(items: range, size: int) -> Iterator[range]:
    ...


@overload
def to_chunks(items: bytes, size: int) -> Iterator[bytes]:
    ...


def to_chunks(items, size):  # type: ignore[no-untyped-def]
    for i in range(0, len(items), size):
        yield items[i : i + size]


def format_error(e: Exception) -> str:
    if isinstance(e, asyncio.TimeoutError):
        # str(e) returns empty string
        return repr(e)

    return str(e)


@functools.cache
def get_project_meta() -> dict:
    toml_path = Path() / 'pyproject.toml'

    with toml_path.open(mode='rb') as pyproject:
        return tomli.load(pyproject)


def get_project_version() -> str:
    return get_project_meta()['tool']['poetry']['version']
