import asyncio
import functools
from pathlib import Path

import tomli


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


def get_project_db_version() -> int:
    db_version = get_project_meta()['tool']['migration']['db_version']
    return int(db_version)
