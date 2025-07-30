import json

from eth_typing import HexStr

from src.common.database import BaseCrud, autocommit
from src.config.settings import network
from src.ssv_operators.typings import SSVValidator


class SSVValidatorCrud(BaseCrud):
    table = f'{network}_ssv_validators'

    async def get_validators(self) -> list[SSVValidator]:
        query = f"""
            SELECT public_key, operator_ids, shares_data
            FROM {self.table}
            """

        res = await self.execute(query)
        validators: list[SSVValidator] = []
        rows = await res.fetchall()

        for public_key, operator_ids, shares_data in rows:
            validators.append(
                SSVValidator(
                    public_key=public_key,
                    operator_ids=json.loads(operator_ids),
                    shares_data=HexStr(shares_data),
                )
            )

        return validators

    @autocommit
    async def save_validators(self, validators: list[SSVValidator]) -> None:
        # It is possible that the same validator is added multiple times,
        # (removed and then added again).
        # So we use ON CONFLICT to update existing records.
        await self.executemany(
            f'INSERT INTO {self.table} VALUES (:public_key, :operator_ids, :shares_data) '
            f'ON CONFLICT (public_key) DO UPDATE '
            f'SET operator_ids = :operator_ids, shares_data = :shares_data',
            [
                {
                    'public_key': validator.public_key,
                    'operator_ids': json.dumps(validator.operator_ids),
                    'shares_data': validator.shares_data,
                }
                for validator in validators
            ],
        )

    async def setup(self) -> None:
        """Creates table."""
        await self.execute(
            f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    public_key TEXT PRIMARY KEY,
                    operator_ids TEXT NOT NULL,
                    shares_data TEXT NOT NULL
                )
            """
        )
