import logging

import aiosqlite

from src.checkpoints.database import CheckpointCrud
from src.common.database import db_client
from src.common.utils import get_project_db_version
from src.db_version.database import DatabaseVersionCrud
from src.ssv_operators.database import SSVOperatorCrud, SSVValidatorCrud

logger = logging.getLogger(__name__)


# Every crud except DatabaseVersionCrud
crud_cls_list = [
    CheckpointCrud,
    SSVOperatorCrud,
    SSVValidatorCrud,
]


async def setup_database() -> None:
    migrations = {
        1: migrate_to_version_1,
    }
    conn = await db_client.get_db_connection()

    # Disable transaction control in sqlite3 module.
    # Manage transactions manually.
    # This allows to run DDL statements in transactional way.
    # https://docs.python.org/3.10/library/sqlite3.html#transaction-control
    conn.isolation_level = None  # noqa
    await conn.execute('BEGIN')

    try:
        db_version_crud = DatabaseVersionCrud(conn)
        await db_version_crud.setup()

        prev_db_version = await db_version_crud.get_version() or 0
        cur_db_version = get_project_db_version()

        for db_version in range(prev_db_version + 1, cur_db_version + 1):
            logger.info('Migrating database to version %s', db_version)
            migration_func = migrations[db_version]
            await migration_func(conn)

        if prev_db_version != cur_db_version:
            await db_version_crud.update_version(cur_db_version)
    except Exception as e:
        logger.warning('Migration aborted due to %r', e)
        await conn.rollback()
        raise
    finally:
        # Close connection because `isolation_level` was changed.
        # The app should use new connection with default settings.
        await db_client.close()


async def migrate_to_version_1(conn: aiosqlite.Connection) -> None:
    for cls in crud_cls_list:
        await cls(conn).setup()
        await conn.commit()
