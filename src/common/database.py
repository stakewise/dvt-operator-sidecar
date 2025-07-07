import sqlite3
from functools import wraps

import aiosqlite

from src.config import settings


class Database:
    def __init__(self) -> None:
        self._conn: aiosqlite.Connection | None = None

    async def get_db_connection(self) -> aiosqlite.Connection:
        if not self._conn:
            self._conn = await aiosqlite.connect(
                settings.database, detect_types=sqlite3.PARSE_COLNAMES
            )
        return self._conn

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
        self._conn = None


db_client = Database()


class TransactionConnection:
    conn: aiosqlite.Connection

    async def __aenter__(self) -> aiosqlite.Connection:
        self.conn = await db_client.get_db_connection()
        return self.conn

    async def __aexit__(self, exc_type, *args, **kwargs) -> None:  # type: ignore
        if not exc_type:
            await self.conn.commit()
        else:
            await self.conn.rollback()


def autocommit(method):  # type: ignore
    @wraps(method)
    async def inner(self, *method_args, **method_kwargs):  # type: ignore
        method_output = await method(self, *method_args, **method_kwargs)
        await self.commit()
        return method_output

    return inner


class BaseCrud:
    conn: aiosqlite.Connection | None
    table: str
    autocommit: bool = False

    def __init__(self, connection: aiosqlite.Connection | None = None):
        self.conn = connection
        if not connection:
            self.autocommit = True

    async def setup(self) -> None:
        raise NotImplementedError

    async def commit(self) -> None:
        if self.autocommit:
            await self.conn.commit()  # type: ignore

    async def execute(self, *args, **kwargs) -> aiosqlite.Cursor:  # type: ignore
        if not self.conn:
            self.conn = await db_client.get_db_connection()
        return await self.conn.execute(*args, **kwargs)

    async def executemany(self, *args, **kwargs) -> aiosqlite.Cursor:  # type: ignore
        if not self.conn:
            self.conn = await db_client.get_db_connection()
        return await self.conn.executemany(*args, **kwargs)
