from unittest import mock

import pytest

from src.common.database import db_client
from src.db_version.database import DatabaseVersionCrud
from src.setup_database import crud_cls_list


async def setup_test_database():
    # Skip connection closing to preserve in-memory database
    await DatabaseVersionCrud().setup()

    for cls in crud_cls_list:
        await cls().setup()


@pytest.fixture()
async def test_db():
    # use in-memory DB
    with mock.patch('src.config.settings.database', ':memory:'):
        await setup_test_database()
        try:
            yield
        finally:
            # DB connection is cached on module level. See src.common.database.db_client.
            # If you don't close connection then DB will persist between tests.
            await db_client.close()
