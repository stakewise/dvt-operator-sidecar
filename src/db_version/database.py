from src.common.database import BaseCrud, autocommit
from src.config.settings import network


class DatabaseVersionCrud(BaseCrud):
    table = f'{network}_db_version'

    async def get_version(self) -> int | None:
        cur = await self.execute(f'SELECT version FROM {self.table}')
        res = await cur.fetchone()
        if not res:
            return None
        return res[0]

    @autocommit
    async def update_version(self, version: int) -> None:
        prev_version = await self.get_version()

        if prev_version is None:
            await self.execute(f'INSERT INTO {self.table} VALUES (?)', (version,))
        else:
            await self.execute(f'UPDATE {self.table} SET version = ?', (version,))

    @autocommit
    async def setup(self) -> None:
        await self.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    version INTEGER
                )
            """
        )
