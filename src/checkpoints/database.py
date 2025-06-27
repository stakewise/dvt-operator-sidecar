from eth_typing import BlockNumber

from src.common.database import BaseCrud, autocommit
from src.config.settings import network


class CheckpointType:
    SSV_VALIDATOR_ADDED = 'ssv_validator_added'


class CheckpointCrud(BaseCrud):
    table = f'{network}_checkpoints'

    async def get_checkpoint_block_number(self, checkpoint_type: str) -> BlockNumber | None:
        """Fetch last block number for checkpoint type"""
        block_number = await self._get_checkpoint_value(checkpoint_type)
        return BlockNumber(block_number) if block_number else None

    async def update_checkpoint_block_number(
        self, checkpoint_type: str, block_number: BlockNumber
    ) -> None:
        return await self._update_checkpoint_value(checkpoint_type, block_number)

    async def update_checkpoint_epoch(self, checkpoint_type: str, epoch: int) -> None:
        return await self._update_checkpoint_value(checkpoint_type, epoch)

    async def _get_checkpoint_value(self, checkpoint_type: str) -> int | None:
        """Fetch last value for checkpoint type"""
        cur = await self.execute(
            f'''SELECT value FROM {self.table} WHERE checkpoint_type = ?''',
            (checkpoint_type,),
        )
        res = await cur.fetchone()
        return res[0] if res else None

    @autocommit
    async def _update_checkpoint_value(self, checkpoint_type: str, value: int) -> None:
        """Set last value for checkpoint type"""
        await self.execute(
            f'INSERT INTO {self.table} '
            'VALUES (:checkpoint_type, :value) '
            'ON CONFLICT (checkpoint_type) DO UPDATE '
            'SET value = :value',
            (checkpoint_type, value),
        )

    async def setup(self) -> None:
        """Creates table."""
        await self.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    checkpoint_type VARCHAR(64) NOT NULL UNIQUE,
                    value INTEGER NOT NULL
                )
            """
        )
