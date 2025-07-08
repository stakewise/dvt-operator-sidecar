from src.db_version.database import DatabaseVersionCrud


class TestDatabaseVersionCrud:
    async def test_get_and_update_version(self, test_db):
        # test init
        crud = DatabaseVersionCrud()
        version = await crud.get_version()
        assert version is None

        # test update
        await crud.update_version(2)
        version = await crud.get_version()
        assert version == 2
